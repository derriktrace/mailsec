"""Export completed, scored benchmark artifacts without reading unscored data.

Usage: python -m mailsec.benchmark_report DIRECTORY [--baseline-holdout DIRECTORY]
Only scores/batch-*.json and their prediction seals are read. Input projections,
ground_truth, source CSV files, and request bodies are never opened.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .benchmark_metrics import compute_metrics


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Benchmark timestamps must include a timezone")
    return parsed.astimezone(UTC)


def load_scored(directory: Path) -> list[dict]:
    """Snapshot the scored-file names, then verify their existing prediction seals."""
    batches = []
    all_ids: set[str] = set()
    for path in sorted((directory / "scores").glob("batch-*.json")):
        score = json.loads(path.read_text())
        batch = score["batch"]
        if type(batch) is not int or not 1 <= batch <= 40 or path.name != f"batch-{batch:02d}.json":
            raise ValueError("Scored batch identity is invalid")
        if score.get("payload_audit") != "passed":
            raise ValueError(f"Batch {batch} has no successful payload audit")
        seal_path = directory / "predictions" / f"batch-{batch:02d}" / "seal.json"
        seal = json.loads(seal_path.read_text())
        results = score["results"]
        ids = [row["row_id"] for row in results]
        if len(ids) != len(set(ids)) or all_ids.intersection(ids):
            raise ValueError("Duplicate local row IDs in scored artifacts")
        all_ids.update(ids)
        predictions = [
            {key: value for key, value in row.items() if key not in {"label", "dataset_annotations"}}
            for row in results
        ]
        if (
            seal["rows"] != len(results)
            or seal["batch"] != batch
            or seal["results_sha256"] != _digest(predictions)
            or seal["questions_sha256"] != score["questions_sha256"]
            or seal["sealed_at"] != score["sealed_at"]
        ):
            raise ValueError(f"Batch {batch} score does not match its prediction seal")
        if _timestamp(seal["sealed_at"]) >= _timestamp(score["labels_opened_at"]):
            raise ValueError(f"Batch {batch} labels were not revealed after sealing")
        phase = "holdout" if batch >= 33 else "development"
        if score["phase"] != phase:
            raise ValueError("Scored phase disagrees with the prespecified split")
        for row in results:
            if row["questions_sha256"] != score["questions_sha256"] or not row.get("text_sha256"):
                raise ValueError("Missing text identity or mismatched row question hash")
        batches.append({**score, "prediction_seal": seal})
    return batches


def _rows(batches: list[dict]) -> list[dict]:
    return [
        {
            **row,
            "batch": batch["batch"],
            "phase": batch["phase"],
            "questions_version": batch.get("questions_version"),
        }
        for batch in batches
        for row in batch["results"]
    ]


def _success(row: dict) -> bool:
    return row.get("output") is not None and not row.get("error")


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    index = (len(values) - 1) * fraction
    lower = math.floor(index)
    return values[lower] + (values[math.ceil(index)] - values[lower]) * (index - lower)


def aggregate(rows: list[dict]) -> dict:
    latencies = [
        float(row["latency_seconds"])
        for row in rows
        if isinstance(row.get("latency_seconds"), (int, float))
        and math.isfinite(row["latency_seconds"])
        and row["latency_seconds"] >= 0
    ]
    usage = Counter()
    models = Counter()
    for row in rows:
        output = row.get("output") or {}
        if output.get("model"):
            models[output["model"]] += 1
        for field in ("input_tokens", "output_tokens"):
            value = output.get("usage", {}).get(field)
            if type(value) is int and value >= 0:
                usage[field] += value
    return {
        "metrics": compute_metrics(rows),
        "resources": {
            "reported_input_tokens": usage["input_tokens"],
            "reported_output_tokens": usage["output_tokens"],
            "attempts": sum(row.get("attempts", 0) for row in rows),
            "latency_observations": len(latencies),
            "latency_seconds_sum": sum(latencies),
            "latency_seconds_mean": statistics.fmean(latencies) if latencies else None,
            "latency_seconds_median": statistics.median(latencies) if latencies else None,
            "latency_seconds_p95": _percentile(latencies, 0.95),
            "models": dict(models),
            "usage_scope": "Tokens reported by retained responses only; charges/usage from failed or discarded retry responses may be absent. Latency sums overlap under concurrency and are not elapsed wall time.",
        },
    }


def _first_seen(rows: list[dict]) -> tuple[list[dict], dict]:
    first = {}
    label_sets: dict[str, set[int]] = defaultdict(set)
    for row in sorted(rows, key=lambda value: (value["batch"], value["row_id"])):
        key = row["text_sha256"]
        first.setdefault(key, row)
        label_sets[key].add(row["label"])
    return list(first.values()), {
        "unique_texts": len(first),
        "excluded_repeated_rows": len(rows) - len(first),
        "text_groups_with_conflicting_labels": sum(len(labels) > 1 for labels in label_sets.values()),
        "selection_rule": "First scored batch, then local row ID; retain the first observation even if it failed.",
    }


def _paired(main: list[dict], baseline: list[dict]) -> dict:
    main = [batch for batch in main if batch["phase"] == "holdout"]
    baseline = [batch for batch in baseline if batch["phase"] == "holdout"]
    left = {batch["batch"]: batch for batch in main}
    right = {batch["batch"]: batch for batch in baseline}
    common = sorted(left.keys() & right.keys())
    if not common:
        return {"status": "not_available", "reason": "No common scored holdout batches", "paired_batches": []}
    candidate_rows, baseline_rows = [], []
    for batch in common:
        candidate, original = left[batch], right[batch]
        first_reveal = min(
            _timestamp(candidate["labels_opened_at"]), _timestamp(original["labels_opened_at"])
        )
        if any(
            _timestamp(arm["prediction_seal"]["sealed_at"]) >= first_reveal for arm in (candidate, original)
        ):
            raise ValueError(
                f"Paired holdout batch {batch}: both arms must be sealed before either arm reveals labels"
            )
        current = {row["row_id"]: row for row in candidate["results"]}
        prior = {row["row_id"]: row for row in original["results"]}
        if current.keys() != prior.keys():
            raise ValueError("Paired holdout arms contain different local row IDs")
        for identifier in sorted(current):
            row, base = current[identifier], prior[identifier]
            if row["text_sha256"] != base["text_sha256"] or row["label"] != base["label"]:
                raise ValueError("Paired holdout row content identity or truth differs")
            candidate_rows.append(row)
            baseline_rows.append(base)
    changes = Counter()
    for row, base in zip(candidate_rows, baseline_rows, strict=True):
        if not _success(row) or not _success(base):
            changes["pairs_with_an_error"] += 1
            if _success(row) and not _success(base):
                changes["recovered_prediction_errors"] += 1
            elif not _success(row) and _success(base):
                changes["new_prediction_errors"] += 1
            continue
        current_choice = row["output"]["answers"]["verdict"]["choice"]
        prior_choice = base["output"]["answers"]["verdict"]["choice"]
        correct = (current_choice == "phishing") == bool(row["label"])
        was_correct = (prior_choice == "phishing") == bool(row["label"])
        changes[
            "improved"
            if correct and not was_correct
            else "regressed"
            if was_correct and not correct
            else "unchanged_correct"
            if correct
            else "unchanged_incorrect"
        ] += 1
        if current_choice == "suspicious" and prior_choice != "suspicious":
            changes["new_suspicious_deferrals"] += 1
        if current_choice != "suspicious" and prior_choice == "suspicious":
            changes["resolved_suspicious_deferrals"] += 1
    return {
        "status": "verified",
        "paired_batches": common,
        "paired_rows": len(candidate_rows),
        "unpaired_candidate_batches": sorted(left.keys() - right.keys()),
        "unpaired_baseline_batches": sorted(right.keys() - left.keys()),
        "timing_audit": "Each arm's prediction seal predates both arms' label-reveal timestamps for every paired batch.",
        "decision_changes": {
            key: changes[key]
            for key in (
                "improved",
                "regressed",
                "unchanged_correct",
                "unchanged_incorrect",
                "pairs_with_an_error",
                "recovered_prediction_errors",
                "new_prediction_errors",
                "new_suspicious_deferrals",
                "resolved_suspicious_deferrals",
            )
        },
        "decision_rule": "Strict binary: phishing positive; all other choices negative. Error pairs are counted separately.",
        "candidate": aggregate(candidate_rows),
        "baseline": aggregate(baseline_rows),
    }


def build_summary(batches: list[dict], baseline: list[dict] | None = None) -> tuple[dict, list[dict]]:
    for arm in (batches, baseline or []):
        holdout_batches = [batch for batch in arm if batch["phase"] == "holdout"]
        if len({batch["questions_sha256"] for batch in holdout_batches}) > 1:
            raise ValueError("Frozen holdout contains multiple question revisions")
        holdout_models = {
            row["output"]["model"]
            for batch in holdout_batches
            for row in batch["results"]
            if _success(row) and row["output"].get("model")
        }
        if len(holdout_models) > 1:
            raise ValueError("Frozen holdout contains multiple model revisions")
    rows = _rows(batches)
    development = [row for row in rows if row["phase"] == "development"]
    holdout = [row for row in rows if row["phase"] == "holdout"]
    unique, duplicates = _first_seen(rows)
    question_groups, subtype_groups, error_groups = defaultdict(list), defaultdict(list), defaultdict(list)
    for row in rows:
        question_groups[row["questions_sha256"]].append(row)
        subtype = str(row.get("dataset_annotations", {}).get("phishing_type", "")).strip() or "unspecified"
        subtype_groups[subtype].append(row)
        if not _success(row):
            error_groups[str(row.get("error") or "No validated output")].append(row)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "complete"
        if {batch["batch"] for batch in batches} == set(range(1, 41))
        and len(rows) == 10000
        and all(len(batch["results"]) == 250 for batch in batches)
        else "partial",
        "completed_batches": [batch["batch"] for batch in batches],
        "expected_batches": 40,
        "expected_rows": 10000,
        "overall_adaptive_sequence": aggregate(rows),
        "development": aggregate(development),
        "frozen_holdout": {
            **aggregate(holdout),
            "completed_batches": sorted({row["batch"] for row in holdout}),
            "expected_batches": list(range(33, 41)),
        },
        "by_questions_hash": {
            key: {
                **aggregate(group),
                "batches": sorted({row["batch"] for row in group}),
                "versions": sorted(
                    {str(row["questions_version"]) for row in group if row.get("questions_version")}
                ),
            }
            for key, group in question_groups.items()
        },
        "first_seen_text_deduplicated": {**aggregate(unique), **duplicates},
        "errors": {
            "total": sum(len(group) for group in error_groups.values()),
            "by_reason": {
                reason: {**aggregate(group), "row_ids": [row["row_id"] for row in group]}
                for reason, group in error_groups.items()
            },
        },
        "posthoc_subtypes": {subtype: aggregate(group) for subtype, group in subtype_groups.items()},
        "scope": [
            "Text-only dataset evaluation; no claim about live Workspace transport, attachment scanning, or operational detection accuracy.",
            "Only scored rows are included. Annotation columns and embedded Keywords: metadata lines were excluded by the prediction workflow.",
            "Overall and development totals describe a sequentially adapted system, not an independent test of its final questions.",
            "Holdout summaries are final-model evidence only while model, questions, preprocessing, and evidence code remain frozen; partial holdouts are explicitly incomplete.",
            "Normalized exact-text grouping is not proof of separation of paraphrased templates. No template-overlap rate is inferred here.",
            "Subtype metrics are posthoc exploratory analyses of already revealed annotations.",
            "Prediction failures remain errors and reduce coverage; they are never counted as clean predictions.",
            "Perfect separation of scored rankings does not imply perfect binary classification, full coverage, or future accuracy.",
            "The phishing score is not established as a calibrated binary probability. Top-k boundary ties use proportional expected positives.",
            "Reported token usage is not a complete billing estimate, especially for discarded response retries.",
        ],
    }
    if baseline is not None:
        summary["paired_baseline_holdout"] = _paired(batches, baseline)
    return summary, rows


def _csv_text(rows: list[dict], fields: list[str]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        # Spreadsheet consumers should not execute externally supplied error/subtype text.
        writer.writerow(
            {
                key: "'" + value if isinstance(value, str) and value and value[:1] in "=+-@" else value
                for key, value in row.items()
                if key in fields
            }
        )
    return stream.getvalue()


def _display(value: Any) -> str:
    return "N/A" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def _markdown(summary: dict) -> str:
    lines = [
        "# Blind benchmark results",
        "",
        f"Status: **{summary['status']}**. "
        f"Scored batches: {len(summary['completed_batches'])}/40; "
        f"rows: {summary['overall_adaptive_sequence']['metrics']['n']}/10000.",
        "",
        "| Scope | Rows | Errors | Coverage | Accuracy | Precision | Recall | FPR | ROC-AUC | AP |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for title, key in (
        ("Adaptive overall", "overall_adaptive_sequence"),
        ("Development", "development"),
        ("Frozen holdout", "frozen_holdout"),
        ("First-seen exact text", "first_seen_text_deduplicated"),
    ):
        metric = summary[key]["metrics"]
        binary, rank = metric["strict_binary"], metric["ranking"]
        values = [
            title,
            metric["n"],
            metric["errors"],
            metric["prediction_coverage"],
            binary["accuracy"],
            binary["precision"],
            binary["recall"],
            binary["false_positive_rate"],
            rank["roc_auc"],
            rank["average_precision"],
        ]
        lines.append("| " + " | ".join(map(_display, values)) + " |")
    lines.extend(
        [
            "",
            "Accuracy, precision, recall, FPR, and rankings above use scored predictions; errors are excluded and coverage is shown. Strict binary means only a phishing choice is positive. Suspicious deferrals and operational flagging metrics are preserved in summary.json.",
            "",
            "## Scope and limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in summary["scope"])
    paired = summary.get("paired_baseline_holdout")
    if paired:
        lines.extend(["", "## Paired baseline holdout", "", f"Status: {paired['status']}."])
        if paired["status"] == "verified":
            changes = paired["decision_changes"]
            lines.append(
                f"Compared {paired['paired_rows']} matched rows: {changes['improved']} improved, "
                f"{changes['regressed']} regressed, {changes['pairs_with_an_error']} pairs with an error. "
                "Both arms were sealed before either arm revealed the corresponding labels."
            )
    return "\n".join(lines) + "\n"


def export_report(directory: str | Path, baseline_holdout: str | Path | None = None) -> dict:
    os.umask(0o077)
    directory = Path(directory)
    batches = load_scored(directory)
    baseline = load_scored(Path(baseline_holdout)) if baseline_holdout else None
    summary, rows = build_summary(batches, baseline)
    flat = []
    for row in rows:
        output = row.get("output") or {}
        verdict = output.get("answers", {}).get("verdict", {}) if _success(row) else {}
        flat.append(
            {
                "row_id": row["row_id"],
                "batch": row["batch"],
                "phase": row["phase"],
                "true_label": row["label"],
                "verdict": verdict.get("choice"),
                "p_phishing": verdict.get("probabilities", {}).get("phishing"),
                "confidence": verdict.get("confidence"),
                "model": output.get("model"),
                "questions_sha256": row["questions_sha256"],
                "questions_version": row.get("questions_version"),
                "text_sha256": row["text_sha256"],
                "error": row.get("error"),
                "attempts": row.get("attempts"),
                "latency_seconds": row.get("latency_seconds"),
            }
        )
    batch_rows = []
    for batch in batches:
        result = aggregate(batch["results"])
        metric, resource = result["metrics"], result["resources"]
        batch_rows.append(
            {
                "batch": batch["batch"],
                "phase": batch["phase"],
                "questions_sha256": batch["questions_sha256"],
                "n": metric["n"],
                "errors": metric["errors"],
                "coverage": metric["prediction_coverage"],
                **{
                    key: metric["strict_binary"][key]
                    for key in (
                        "tp",
                        "tn",
                        "fp",
                        "fn",
                        "accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "false_positive_rate",
                    )
                },
                "roc_auc": metric["ranking"]["roc_auc"],
                "average_precision": metric["ranking"]["average_precision"],
                "suspicious": metric["suspicious_deferral"]["count"],
                **{
                    key: resource[key]
                    for key in (
                        "reported_input_tokens",
                        "reported_output_tokens",
                        "attempts",
                        "latency_seconds_mean",
                    )
                },
            }
        )
    files = {
        "summary.json": json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        "results.csv": _csv_text(
            flat,
            [
                "row_id",
                "batch",
                "phase",
                "true_label",
                "verdict",
                "p_phishing",
                "confidence",
                "model",
                "questions_sha256",
                "questions_version",
                "text_sha256",
                "error",
                "attempts",
                "latency_seconds",
            ],
        ),
        "batches.csv": _csv_text(
            batch_rows,
            [
                "batch",
                "phase",
                "questions_sha256",
                "n",
                "errors",
                "coverage",
                "tp",
                "tn",
                "fp",
                "fn",
                "accuracy",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "roc_auc",
                "average_precision",
                "suspicious",
                "reported_input_tokens",
                "reported_output_tokens",
                "attempts",
                "latency_seconds_mean",
            ],
        ),
        "summary.md": _markdown(summary),
    }
    target = directory / "report"
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, content in files.items():
        temporary = target / (name + ".tmp")
        temporary.write_text(content)
        temporary.replace(target / name)
    return {
        "status": summary["status"],
        "batches": len(batches),
        "rows": len(rows),
        "report_directory": str(target.resolve()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--baseline-holdout", type=Path)
    args = parser.parse_args()
    print(json.dumps(export_report(args.directory, args.baseline_holdout), indent=2))


if __name__ == "__main__":
    main()
