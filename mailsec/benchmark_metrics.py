"""Evaluation of already-sealed predictions, without I/O or model calls.

Labels must already be normalized: 0 = legitimate, 1 = phishing. Errors never
become benign predictions. Ranking uses the model's phishing score; no claim of
binary probability calibration is made. Ties are evaluated without row-order bias.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from typing import Any

VERDICTS = ("clean", "spam", "suspicious", "phishing")


def _ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _binary(observations: list[tuple[int, bool]]) -> dict[str, Any]:
    tp = sum(label == 1 and prediction for label, prediction in observations)
    fp = sum(label == 0 and prediction for label, prediction in observations)
    tn = sum(label == 0 and not prediction for label, prediction in observations)
    fn = sum(label == 1 and not prediction for label, prediction in observations)
    recall, specificity = _ratio(tp, tp + fn), _ratio(tn, tn + fp)
    return {
        "evaluated_n": len(observations),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": _ratio(tp, tp + fp),
        "recall": recall,
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
        "accuracy": _ratio(tp + tn, len(observations)),
        "balanced_accuracy": (recall + specificity) / 2
        if recall is not None and specificity is not None
        else None,
    }


def _rank_metrics(observations: list[tuple[int, float]]) -> dict[str, Any]:
    # Each tuple is (score, positive count, total count), highest score first.
    grouped: dict[float, list[int]] = {}
    for label, score in observations:
        group = grouped.setdefault(score, [0, 0])
        group[0] += label
        group[1] += 1
    groups = [(score, *counts) for score, counts in sorted(grouped.items(), reverse=True)]
    n = len(observations)
    positives = sum(label for label, _ in observations)
    negatives = n - positives
    seen_positive = seen_total = 0
    ap = wins = 0.0
    for _, positive, total in groups:
        seen_positive += positive
        seen_total += total
        ap += positive * seen_positive / seen_total
        negative = total - positive
        lower_negatives = negatives - (seen_total - seen_positive)
        wins += positive * (lower_negatives + 0.5 * negative)

    top_k: dict[str, Any] = {}
    for percent in (1, 5, 10):
        k = math.ceil(n * percent / 100)
        selected = 0
        expected_positives = 0.0
        boundary = None
        for score, positive, total in groups:
            remaining = k - selected
            if remaining <= 0:
                break
            take = min(total, remaining)
            expected_positives += positive * take / total
            selected += take
            if selected == k:
                boundary = {
                    "score": score,
                    "group_size": total,
                    "positives_in_group": positive,
                    "selected_from_group": take,
                    "selected_fraction": take / total,
                    "split_tie": take < total,
                }
        top_k[f"top_{percent}_percent"] = {
            "k": k,
            "expected_true_positives": expected_positives,
            "precision": _ratio(expected_positives, k),
            "recall": _ratio(expected_positives, positives),
            "boundary": boundary,
        }

    positive_scores = [score for label, score in observations if label == 1]
    negative_scores = [score for label, score in observations if label == 0]
    return {
        "evaluated_n": n,
        "positives": positives,
        "negatives": negatives,
        "roc_auc": _ratio(wins, positives * negatives),
        "average_precision": _ratio(ap, positives),
        "strict_perfect_separation": min(positive_scores) > max(negative_scores)
        if positives and negatives
        else None,
        "top_k": top_k,
        "score_interpretation": "Jev p(phishing) is a ranking score, not a validated calibrated binary probability.",
        "tie_policy": {
            "roc_auc": "A positive-negative score tie receives half credit.",
            "average_precision": "Sum group-end precision times recall increment, with equal-score rows grouped.",
            "top_k": "k=ceil(scored_n*percent/100). A boundary tie contributes its proportional positive share; this is expected performance under random tie breaking, not a selected row list.",
        },
    }


def compute_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Compute metrics from predictions sealed before labels were revealed.

    A row with ``output is None`` or a truthy ``error`` is an error. All main
    classifier/ranking denominators exclude such rows; coverage and all-row
    accuracy expose this exclusion. Undefined divisions return None, never NaN.
    Suspicious counts negative in the explicitly named strict binary view and
    positive in the operational flag view; the separate selective view defers it.
    This function does not deduplicate; callers should evaluate first-seen rows
    separately when the sequential benchmark contains repeated email content.
    """
    labels = {"0": 0, "1": 0}
    scored_labels = {"0": 0, "1": 0}
    errors_by_label = {"0": 0, "1": 0}
    verdict_counts = dict.fromkeys(VERDICTS, 0)
    confusion = {key: dict.fromkeys(VERDICTS, 0) for key in labels}
    scored: list[tuple[int, str, float]] = []
    n = 0
    for row in rows:
        label = row["label"]
        if type(label) is not int or label not in (0, 1):
            raise ValueError("Benchmark labels must be normalized integers 0 or 1")
        n += 1
        labels[str(label)] += 1
        output = row.get("output")
        if output is None or row.get("error"):
            errors_by_label[str(label)] += 1
            continue
        try:
            answer = output["answers"]["verdict"]
            verdict = answer["choice"]
            score = answer["probabilities"]["phishing"]
        except (KeyError, TypeError) as exc:
            raise ValueError("Expected a validated Jev verdict output") from exc
        if verdict not in VERDICTS or isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ValueError("Expected a validated Jev verdict and numeric phishing score")
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("Phishing score must be finite and between zero and one")
        scored.append((label, verdict, float(score)))
        scored_labels[str(label)] += 1
        verdict_counts[verdict] += 1
        confusion[str(label)][verdict] += 1

    strict = _binary([(label, verdict == "phishing") for label, verdict, _ in scored])
    strict["positive_rule"] = "choice == phishing; clean, spam, and suspicious are negative in this view"
    strict["accuracy_all_rows_errors_incorrect"] = _ratio(strict["tp"] + strict["tn"], n)
    threshold = _binary([(label, score >= 0.5) for label, _, score in scored])
    threshold["threshold"] = 0.5
    threshold["positive_rule"] = "phishing ranking score >= 0.5"
    threshold["accuracy_all_rows_errors_incorrect"] = _ratio(threshold["tp"] + threshold["tn"], n)
    flagged = _binary([(label, verdict in ("phishing", "suspicious")) for label, verdict, _ in scored])
    flagged["positive_rule"] = "choice in {phishing, suspicious}; measures analyst flagging burden"
    decided = [(label, verdict == "phishing") for label, verdict, _ in scored if verdict != "suspicious"]
    deferred = verdict_counts["suspicious"]
    return {
        "n": n,
        "scored_n": len(scored),
        "errors": n - len(scored),
        "label_counts": labels,
        "scored_label_counts": scored_labels,
        "errors_by_label": errors_by_label,
        "verdict_counts": verdict_counts,
        "confusion": confusion,
        "prediction_coverage": _ratio(len(scored), n),
        "strict_binary": strict,
        "threshold_binary": threshold,
        "operational_flagged": flagged,
        "suspicious_deferral": {
            "count": deferred,
            "rate_of_scored": _ratio(deferred, len(scored)),
            "rate_of_all_rows": _ratio(deferred, n),
            "decision_coverage_all_rows": _ratio(len(decided), n),
            "decision_coverage_scored_rows": _ratio(len(decided), len(scored)),
            "selective_binary": _binary(decided),
        },
        "ranking": _rank_metrics([(label, score) for label, _, score in scored]),
        "denominators": {
            "labels": "0=legitimate; 1=phishing. Label counts include every row.",
            "confusion": "2x4 counts include scored rows only; failed rows are errors_by_label.",
            "binary_and_ranking": "Errors are excluded; evaluated_n and prediction_coverage expose coverage.",
            "selective": "Both suspicious choices and errors are excluded from decided predictions.",
            "undefined": "Metrics with zero denominators are null.",
        },
    }
