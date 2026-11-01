import json

import pytest

from mailsec.benchmark_metrics import compute_metrics


def row(label, verdict, score):
    if verdict is None:
        return {"label": label, "output": None, "error": "provider failed"}
    return {
        "label": label,
        "output": {
            "answers": {
                "verdict": {
                    "choice": verdict,
                    "probabilities": {"phishing": score},
                }
            }
        },
    }


def test_binary_views_confusion_and_error_denominators():
    data = [
        row(1, "phishing", 0.9),
        row(0, "phishing", 0.8),
        row(1, "suspicious", 0.4),
        row(0, "spam", 0.1),
        row(1, None, None),
        row(0, "clean", 0.05),
    ]
    metrics = compute_metrics(data)
    assert metrics["n"] == 6 and metrics["errors"] == 1 and metrics["scored_n"] == 5
    assert metrics["label_counts"] == {"0": 3, "1": 3}
    assert metrics["errors_by_label"] == {"0": 0, "1": 1}
    assert metrics["confusion"]["1"] == {"clean": 0, "spam": 0, "suspicious": 1, "phishing": 1}
    binary = metrics["strict_binary"]
    assert {key: binary[key] for key in ("tp", "tn", "fp", "fn")} == {"tp": 1, "tn": 2, "fp": 1, "fn": 1}
    assert binary["precision"] == binary["recall"] == binary["f1"] == 0.5
    assert binary["accuracy"] == 0.6
    assert binary["accuracy_all_rows_errors_incorrect"] == 0.5
    assert binary["false_positive_rate"] == pytest.approx(1 / 3)
    assert binary["balanced_accuracy"] == pytest.approx(7 / 12)
    assert metrics["operational_flagged"]["recall"] == 1
    assert metrics["suspicious_deferral"]["decision_coverage_all_rows"] == pytest.approx(4 / 6)
    assert metrics["suspicious_deferral"]["rate_of_scored"] == 0.2


def test_ranking_oracle_and_threshold_boundary():
    metrics = compute_metrics(
        [row(1, "phishing", 0.9), row(0, "phishing", 0.8), row(1, "phishing", 0.5), row(0, "clean", 0.1)]
    )
    ranking = metrics["ranking"]
    assert ranking["roc_auc"] == 0.75
    assert ranking["average_precision"] == pytest.approx((1 + 2 / 3) / 2)
    assert ranking["strict_perfect_separation"] is False
    assert metrics["threshold_binary"]["tp"] == 2
    assert ranking["top_k"]["top_1_percent"]["precision"] == 1
    assert ranking["top_k"]["top_1_percent"]["recall"] == 0.5


def test_ties_are_groupwise_and_invariant_to_row_order():
    data = [
        row(1, "suspicious", 0.4),
        row(0, "suspicious", 0.4),
        row(0, "suspicious", 0.4),
        row(1, "suspicious", 0.4),
    ]
    metrics = compute_metrics(data)
    assert metrics == compute_metrics(reversed(data))
    ranking = metrics["ranking"]
    assert ranking["roc_auc"] == ranking["average_precision"] == 0.5
    assert ranking["strict_perfect_separation"] is False
    top = ranking["top_k"]["top_1_percent"]
    assert top["k"] == 1 and top["precision"] == 0.5 and top["recall"] == 0.25
    assert top["boundary"]["split_tie"] and top["boundary"]["selected_fraction"] == 0.25
    assert metrics["suspicious_deferral"]["decision_coverage_all_rows"] == 0


def test_partially_tied_ranking_matches_pairwise_oracle():
    data = [
        row(1, "phishing", 0.9),
        row(0, "phishing", 0.9),
        row(1, "phishing", 0.9),
        row(0, "suspicious", 0.5),
        row(1, "suspicious", 0.5),
        row(0, "clean", 0.1),
    ]
    ranking = compute_metrics(data)["ranking"]
    # Nine positive-negative pairs: five wins, three ties, one loss.
    assert ranking["roc_auc"] == pytest.approx(6.5 / 9)
    assert ranking["average_precision"] == pytest.approx((2 * (2 / 3) + 3 / 5) / 3)


@pytest.mark.parametrize("label,expected_ap", [(0, None), (1, 1.0)])
def test_single_class_rank_metrics_are_explicit(label, expected_ap):
    metrics = compute_metrics([row(label, "clean", 0.2), row(label, "phishing", 0.8)])
    assert metrics["ranking"]["roc_auc"] is None
    assert metrics["ranking"]["average_precision"] == expected_ap
    assert metrics["ranking"]["strict_perfect_separation"] is None
    assert metrics["strict_binary"]["balanced_accuracy"] is None


@pytest.mark.parametrize("data", [[], [row(1, None, None), row(0, None, None)]])
def test_empty_and_all_errors_serialize_without_nan(data):
    metrics = compute_metrics(data)
    assert metrics["scored_n"] == 0
    assert metrics["strict_binary"]["accuracy"] is None
    assert metrics["ranking"]["roc_auc"] is None
    assert metrics["ranking"]["average_precision"] is None
    assert metrics["ranking"]["top_k"]["top_10_percent"]["k"] == 0
    json.dumps(metrics, allow_nan=False)


def test_error_flag_never_reuses_a_stale_successful_output():
    item = row(1, "phishing", 0.9)
    item["error"] = "retry failed"
    assert compute_metrics([item])["errors"] == 1


@pytest.mark.parametrize("label", [True, "1", -1, 2])
def test_rejects_unnormalized_labels(label):
    with pytest.raises(ValueError, match="normalized"):
        compute_metrics([row(label, "clean", 0.1)])


def test_top_k_uses_percentage_of_scored_rows_and_perfect_ranking():
    data = [
        row(int(index >= 50), "phishing" if index >= 50 else "clean", index / 100) for index in range(100)
    ]
    result = compute_metrics(data)["ranking"]
    assert result["roc_auc"] == result["average_precision"] == 1
    assert result["strict_perfect_separation"] is True
    assert [entry["k"] for entry in result["top_k"].values()] == [1, 5, 10]
    assert result["top_k"]["top_10_percent"]["recall"] == 0.2
