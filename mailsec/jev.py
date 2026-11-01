import json
import math
import time
from pathlib import Path

import httpx

from .outbound import bounded_response

QUESTIONS = json.loads(Path(__file__).with_name("questions.json").read_text())
VERDICTS = tuple(QUESTIONS["verdict"]["criteria"])


class JevError(Exception):
    """Sanitized provider failure; never holds request headers or secret values."""


def probability(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JevError("Jev returned a nonnumeric probability")
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise JevError("Jev returned an invalid probability")
    return value


def validate_response(data, questions=None):
    questions = QUESTIONS if questions is None else questions
    try:
        if not isinstance(data["model"], str) or not data["model"]:
            raise JevError("Missing model version")
        answers = data["answers"]
        if set(answers) != set(questions):
            raise JevError("Jev response did not answer exactly the configured questions")
        for key, question in questions.items():
            answer = answers[key]
            fields = {'type', 'noul'} if question['type'] == 'noul' else {'type', 'choice', 'confidence', 'probabilities'}
            if not isinstance(answer, dict) or set(answer) != fields:
                raise JevError("Unexpected answer fields")
            if answer['type'] != question['type']:
                raise JevError("Invalid answer type")
            if question['type'] == 'noul':
                probability(answer['noul'])
            elif question['type'] == 'choice':
                choices = question['criteria']
                if answer['choice'] not in choices:
                    raise JevError("Invalid choice")
                probability(answer['confidence'])
                probs = answer['probabilities']
                if set(probs) != set(choices) or abs(sum(probability(v) for v in probs.values()) - 1) > .02:
                    raise JevError("Invalid choice probability distribution")
                if probs[answer['choice']] + 1e-6 < max(probs.values()):
                    raise JevError("Choice does not match highest probability")
            else:
                raise JevError("Unsupported question type")
        for key in ("input_tokens", "output_tokens"):
            value = data["usage"][key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise JevError("Invalid usage")
    except (KeyError, TypeError, AttributeError) as exc:
        raise JevError("Malformed Jev response") from exc
    return data


class JevClient:
    provider = "jev"

    def __init__(self, api_key, model="jev-latest", transport=None, sleeper=time.sleep, questions=None,
                 timeout=45, max_attempts=3, before_request=None):
        self.api_key, self.model, self.transport, self.sleep = api_key, model, transport, sleeper
        self.questions = QUESTIONS if questions is None else questions
        self.timeout, self.max_attempts = timeout, max_attempts
        self.before_request = before_request

    def evaluate(self, evidence, questions=None):
        if not self.api_key:
            raise JevError("TYPESAFE_API_KEY is not configured")
        questions = self.questions if questions is None else questions
        payload = {"model": self.model, "state": evidence, "questions": questions}
        if len(json.dumps(payload).encode()) > 110_000:
            raise JevError("Evidence exceeds the request budget; review the message locally")
        with httpx.Client(transport=self.transport, timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
            for attempt in range(self.max_attempts):
                if self.before_request is not None:
                    self.before_request()
                try:
                    response = bounded_response(client, "POST", "https://api.typesafe.ai/v1/systemone", json=payload,
                                           max_bytes=1024 * 1024, total_seconds=self.timeout,
                                           headers={"Authorization": f"Bearer {self.api_key}"})
                except ValueError:
                    raise JevError("Jev returned an oversized or unsupported response") from None
                except httpx.TransportError:
                    if attempt + 1 < self.max_attempts:
                        self.sleep(2 ** attempt)
                        continue
                    raise JevError(f"Jev connection failed after {self.max_attempts} attempt(s)") from None
                if response.status_code in (429, 500, 502, 503, 504, 529) and attempt + 1 < self.max_attempts:
                    try:
                        delay = min(15, max(0, float(response.headers.get("retry-after", 2 ** attempt))))
                    except ValueError:
                        delay = 2 ** attempt
                    self.sleep(delay)
                    continue
                if response.status_code != 200:
                    if response.status_code == 400:
                        try:
                            detail = response.json().get('detail')
                        except (ValueError, AttributeError):
                            detail = None
                        if detail == 'max_tokens_exceeded':
                            raise JevError('Jev context limit exceeded; review the message locally')
                    raise JevError(f"Jev returned HTTP {response.status_code}")
                try:
                    data = response.json()
                except (ValueError, RecursionError):
                    raise JevError("Jev returned invalid JSON") from None
                try:
                    return validate_response(data, questions)
                except JevError:
                    if attempt + 1 < self.max_attempts:
                        self.sleep(2 ** attempt)
                        continue
                    raise
        raise JevError("Jev request exhausted retries")


def passive_policy(output):
    verdict = output["answers"]["verdict"]
    action = {"clean": "none", "spam": "label_spam", "suspicious": "analyst_review",
              "phishing": "quarantine"}[verdict["choice"]]
    reasons = ["Passive mode: mailbox changes are disabled."]
    if verdict["confidence"] < .6:
        action = "analyst_review"
        reasons.append("Choice confidence is below the provisional review threshold (0.6).")
    return {"verdict": verdict["choice"], "recommended_action": action, "executed_action": "none",
            "mode": "passive", "reasons": reasons}
