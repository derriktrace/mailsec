"""Security boundary regressions using synthetic mail and local temporary stores."""

import copy

import pytest
from privacy_helpers import authorize_test_provider
from sqlalchemy import select

from mailsec.config import Settings
from mailsec.jev import JevError
from mailsec.mailbox_actions import list_actions
from mailsec.pipeline import Pipeline
from mailsec.storage import jobs


class FakeJev:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure

    def evaluate(self, evidence, questions=None):
        self.calls.append(copy.deepcopy(evidence))
        if self.failure:
            raise self.failure
        return {"model": "jev-test-pinned", "usage": {"input_tokens": 10, "output_tokens": 5},
                "answers": {"verdict": {"choice": "clean", "confidence": .99,
                    "probabilities": {"clean": .99, "spam": .005, "suspicious": .004, "phishing": .001}},
                    "deceptive_identity": {"noul": .01}, "requests_sensitive_action": {"noul": .01},
                    "business_context_anomaly": {"noul": .01},
                    "recommended_security_action": {"choice": "deliver"}}}


class FakeInspector:
    def __init__(self, result=None, failure=None):
        self.result = result or {"status": "complete", "antivirus": {"status": "clean", "engine_version": "1",
                "signature_version": "123", "signatures_current": True}, "findings": [], "attachments": [],
                "urls": [], "coverage": {"antivirus": "complete"}, "stats": {}}
        self.failure = failure

    def inspect(self, raw):
        if self.failure:
            raise self.failure
        return copy.deepcopy(self.result)


class FakeReputation:
    def inspect(self, urls):
        assert urls == []
        return {"complete": True, "results": [], "remote_pages_visited": False}


@pytest.fixture
def pipeline(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'protection.db'}", model="jev-test-pinned",
        organization={"domains": ["recipient.example"]}, enforcement_mode="auto_quarantine",
        authorized_mailboxes=["analyst@recipient.example"])
    result = Pipeline(settings, jev=FakeJev(), inspector=FakeInspector(), reputation=FakeReputation())
    authorize_test_provider(settings, result.store)
    yield result
    result.store.engine.dispose()


def evidence():
    return {"message": {"sender": {"address": "accounts@vendor.example", "domain": "vendor.example"},
                        "mailbox": "analyst@recipient.example"},
            "body": "Your routine receipt is ready.", "authentication": {"status": "verified", "dmarc": "pass"},
            "organization_context": {"known_vendor": "Vendor"},
            "inspection": FakeInspector().result, "url_inspection": {"complete": True, "results": []}}


def evaluate(pipeline, value):
    versions = {"questions": "synthetic-pinned", "parser": "synthetic-pinned"}
    output = pipeline._evaluate(value, versions)
    return output, versions


def test_exact_context_cache_reuses_identical_evidence_and_zeroes_billable_usage(pipeline):
    original, first = evaluate(pipeline, evidence())
    cached, second = evaluate(pipeline, evidence())
    assert len(pipeline.jev.calls) == 1
    assert first["jev_cache_hit"] is False and second["jev_cache_hit"] is True
    assert original["usage"]["input_tokens"] == 10
    assert cached["usage"] == {"input_tokens": 0, "output_tokens": 0}
    assert cached["cached_original_usage"] == original["usage"]


@pytest.mark.parametrize("changed", ["sender", "mailbox", "authentication", "organization", "antivirus_signatures"])
def test_same_body_never_reuses_judgment_across_changed_security_context(pipeline, changed):
    original = evidence()
    evaluate(pipeline, original)
    other = copy.deepcopy(original)
    if changed == "sender":
        other["message"]["sender"] = {"address": "accounts@unrelated.example", "domain": "unrelated.example"}
    elif changed == "mailbox":
        other["message"]["mailbox"] = "other@recipient.example"
    elif changed == "authentication":
        other["authentication"] = {"status": "unverified", "dmarc": "unknown"}
    elif changed == "organization":
        other["organization_context"] = {"known_vendor": None}
    else:
        other["inspection"]["antivirus"]["signature_version"] = "124"
    assert other["body"] == original["body"]
    _, versions = evaluate(pipeline, other)
    assert len(pipeline.jev.calls) == 2 and versions["jev_cache_hit"] is False


@pytest.mark.parametrize("coverage", ["absent", "partial", "unavailable", "url_unknown"])
def test_missing_inspection_cannot_cache_a_clean_semantic_answer(pipeline, coverage):
    value = evidence()
    if coverage == "absent":
        del value["inspection"]
    elif coverage == "url_unknown":
        value["url_inspection"] = {"complete": False, "results": [{"status": "unavailable"}]}
    else:
        value["inspection"]["status"] = coverage
    evaluate(pipeline, value)
    _, versions = evaluate(pipeline, value)
    assert len(pipeline.jev.calls) == 2 and versions["jev_cache_hit"] is False


def test_provider_expiry_bounds_exact_judgment_cache(pipeline):
    clock = [100.0]
    pipeline.cache.clock = lambda: clock[0]
    value = evidence()
    value["url_inspection"]["results"] = [{"status": "not_listed", "expires_at": 105.0}]
    evaluate(pipeline, value)
    clock[0] = 106.0
    _, versions = evaluate(pipeline, value)
    assert len(pipeline.jev.calls) == 2 and versions["jev_cache_hit"] is False


def raw_email():
    return b"From: sender@vendor.example\r\nTo: analyst@recipient.example\r\nSubject: Synthetic\r\n\r\nRoutine text."


def test_inspector_exception_finishes_job_with_review_and_sanitized_error(pipeline):
    marker = "private-email-and-provider-key-not-for-output"
    pipeline.inspector = FakeInspector(failure=RuntimeError(marker))
    message = pipeline.ingest(raw_email())
    result = pipeline.process_one()
    assert result["status"] == "error" and result["run_id"] and result["verdict"] is None
    detail = pipeline.store.detail(message["id"])
    assert detail["message"]["status"] == "error"
    assert detail["runs"][0]["policy"]["eligible_action"] == "flag"
    assert marker not in result["error"] and marker not in detail["runs"][0]["error"]
    with pipeline.store.engine.connect() as db:
        assert db.execute(select(jobs.c.status).where(jobs.c.message_id == message["id"])).scalar_one() == "error"
    assert pipeline.process_one() is None
    assert pipeline.jev.calls == []


@pytest.mark.parametrize("failure", [JevError("Jev provider unavailable"), RuntimeError("private-secret-marker")])
def test_hard_detection_survives_jev_failure_and_enqueues_quarantine_without_send(pipeline, failure):
    pipeline.inspector.result.update(status="partial", antivirus={"status": "malicious", "malware_signature": "Eicar-Signature"},
        findings=[{"kind": "antivirus_signature", "severity": "critical", "evidence_ref": "message"}])
    pipeline.jev = FakeJev(failure)
    message = pipeline.ingest(raw_email(), provider="gmail", provider_message_id="synthetic-provider-id",
                              mailbox="analyst@recipient.example")
    result = pipeline.process_one()
    assert result["status"] == "error" and result["verdict"] == "phishing"
    run = pipeline.store.detail(message["id"])["runs"][0]
    assert run["output"] is None and run["policy"]["hard_detection"]
    assert run["policy"]["eligible_action"] == "quarantine"
    assert run["evidence"]["inspection"]["antivirus"]["status"] == "malicious"
    ledger = list_actions(pipeline.store, message["id"])
    assert len(ledger) == 1 and ledger[0]["action"] == "quarantine"
    assert ledger[0]["status"] == "pending" and ledger[0]["analysis_run_id"] == result["run_id"]
    assert ledger[0]["notification_status"] is None
    assert "private-secret-marker" not in result["error"]


def test_inspector_cache_telemetry_does_not_defeat_security_context_cache(pipeline):
    original = evidence()
    evaluate(pipeline, original)
    repeated = copy.deepcopy(original)
    repeated['inspection']['stats'].update(message_cache_hit=True, elapsed_seconds=0.001, attachment_cache_hits=2)
    repeated['inspection']['antivirus'].update(signature_age_hours=1.5, cache_hit=True)
    _, versions = evaluate(pipeline, repeated)
    assert versions['jev_cache_hit'] and len(pipeline.jev.calls) == 1



def test_oversize_gmail_rejection_retains_review_intent_for_action_recovery(pipeline):
    from mailsec.mailbox_actions import reconcile_committed_actions
    pipeline.settings.max_message_bytes = 10
    item = pipeline.ingest(b'From: test@example.test\r\n\r\nOversized synthetic payload.',
        provider='gmail', mailbox='analyst@recipient.example', provider_message_id='oversized-review')
    detail = pipeline.store.detail(item['id'])
    assert detail['message']['status'] == 'error'
    assert detail['runs'][0]['policy']['eligible_action'] == 'flag'
    assert not detail['runs'][0]['policy']['hard_detection']
    assert reconcile_committed_actions(pipeline.settings, pipeline.store)['enqueued'] == 1
    assert list_actions(pipeline.store, message_id=item['id'])[0]['action'] == 'flag'
