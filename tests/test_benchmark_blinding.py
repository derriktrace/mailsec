import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from mailsec import benchmark


def test_content_projection_drops_embedded_annotation_not_subject_or_body():
    text = "Subject: Please review\nA normal sentence.\nKeywords: TARGET_SENTINEL\nA final sentence."
    projected = benchmark.content_only(text)
    assert projected == "Subject: Please review\nA normal sentence.\nA final sentence."
    evidence = benchmark.text_evidence(projected)
    assert evidence["body"] == projected
    assert evidence["quality"]["missing_sender"] is True
    assert evidence["quality"]["invalid_sender_address"] is False
    assert evidence["authentication"]["spf"] == "unknown"


def test_prediction_cannot_access_labels_and_score_requires_untampered_seal(tmp_path, monkeypatch):
    rows = [{"row_id": f"row-{i:05d}", "text": f"Your order {i} has shipped.",
             "text_sha256": benchmark.digest(f"your order {i} has shipped.")} for i in range(250)]
    benchmark.save(tmp_path / "inputs/batch-01.json", rows)
    benchmark.save(tmp_path / "manifest.json", {"source_sha256": "source-hash",
                   "batch_hashes": {"1": {"input_sha256": benchmark.digest(rows)}}})
    questions_path = Path(benchmark.__file__).with_name("questions.json")
    original_read = benchmark.read
    sent = []

    def guarded_read(path):
        assert "ground_truth" not in str(path), "Predictor tried to read labels"
        return original_read(path)

    def provider(request):
        payload = json.loads(request.content)
        sent.append(payload)
        assert set(payload) == {"model", "state", "questions"}
        assert "row_id" not in payload["state"]
        assert "TARGET_SENTINEL" not in request.content.decode()
        return httpx.Response(200, json={"model": benchmark.MODEL,
            "answers": {"verdict": {"type": "choice", "choice": "clean", "confidence": 1.0,
                "probabilities": {"clean": 1.0, "spam": 0.0, "suspicious": 0.0, "phishing": 0.0}},
                **{key: {"type": "noul", "noul": 0.0} for key in
                   (key for key, question in payload["questions"].items() if question["type"] == "noul")},
                "recommended_security_action": {"type": "choice", "choice": "deliver", "confidence": 1.,
                    "probabilities": {"deliver": 1., "junk": 0., "review": 0., "quarantine": 0., "block": 0.}}},
            "usage": {"input_tokens": 100, "output_tokens": 20}})

    original_client = httpx.Client
    monkeypatch.setattr(benchmark, "read", guarded_read)
    monkeypatch.setattr(benchmark.httpx, "Client", lambda **kwargs:
                        original_client(transport=httpx.MockTransport(provider), **kwargs))
    monkeypatch.setattr(benchmark.Settings, "load", lambda: SimpleNamespace(api_key="test-only"))
    monkeypatch.setattr(benchmark.time, "sleep", lambda _: None)
    seal = benchmark.predict(tmp_path, 1, questions_path, workers=4)
    assert seal["rows"] == len(sent) == 250
    assert seal["errors"] == 0
    assert (tmp_path / "predictions/batch-01/seal.json").exists()
    # Tampering must be rejected before the label reader can be called.
    predictions = original_read(tmp_path / "predictions/batch-01/results.json")
    predictions[0]["output"]["answers"]["verdict"]["choice"] = "phishing"
    benchmark.save(tmp_path / "predictions/batch-01/results.json", predictions)
    with pytest.raises(ValueError, match="seal failed"):
        benchmark.score(tmp_path, 1)


def test_score_never_reads_truth_without_a_prediction_seal(tmp_path, monkeypatch):
    original_read = benchmark.read

    def guarded_read(path):
        assert "ground_truth" not in str(path)
        return original_read(path)

    monkeypatch.setattr(benchmark, "read", guarded_read)
    with pytest.raises(FileNotFoundError):
        benchmark.score(tmp_path, 1)
