"""Offline, reproducible evaluation of declared discovery schedules."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any, Mapping

_LABELS = {"relevant", "known_false_positive", "unlabeled_unknown"}
_OPAQUE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

def _exclusive_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir(): raise ValueError("unsafe output")
    temporary=path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(value,stream,ensure_ascii=False,indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally: temporary.unlink(missing_ok=True)


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def load_evaluation(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(source, Mapping):
        value = json.loads(json.dumps(source))
    else:
        with Path(source).open("rb") as handle:
            data = handle.read(8_388_609)
        if len(data) > 8_388_608:
            raise ValueError("evaluation input too large")
        value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("invalid evaluation")
    required = {"version", "dataset_card", "candidates", "splits", "query_results", "schedules", "budgets"}
    if set(value) != required or value.get("version") != 1:
        raise ValueError("invalid evaluation shape")
    card = value["dataset_card"]
    if not isinstance(card, dict) or set(card) != {"dataset_id", "created_at", "synthetic", "candidate_ids_fixed_before_runs", "test_labels_not_used_for_tuning", "split_grouping", "limitations"}:
        raise ValueError("invalid dataset card")
    if card.get("candidate_ids_fixed_before_runs") is not True or card.get("test_labels_not_used_for_tuning") is not True or not isinstance(card.get("synthetic"), bool):
        raise ValueError("invalid evaluation declarations")
    if card.get("split_grouping") not in {"candidate_id", "organization_group"} or not _OPAQUE.fullmatch(str(card.get("dataset_id", ""))):
        raise ValueError("invalid evaluation grouping")
    if not isinstance(card.get("limitations"), list) or not card["limitations"] or not all(isinstance(x, str) and x for x in card["limitations"]):
        raise ValueError("missing limitations")
    candidates = value["candidates"]
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("invalid candidates")
    ids: set[str] = set()
    for row in candidates:
        if (not isinstance(row, dict) or set(row) != {"candidate_id", "label", "families"} or
                not isinstance(row.get("candidate_id"), str) or not _OPAQUE.fullmatch(row["candidate_id"]) or
                row.get("label") not in _LABELS or row["candidate_id"] in ids or
                not isinstance(row.get("families"), list) or not row["families"] or
                any(not isinstance(x, str) or not _OPAQUE.fullmatch(x) for x in row["families"])):
            raise ValueError("invalid candidate")
        ids.add(row["candidate_id"])
    splits = value["splits"]
    if not isinstance(splits, dict) or set(splits) != {"train", "test"}:
        raise ValueError("invalid splits")
    train, test = splits["train"], splits["test"]
    if not all(isinstance(x, list) and all(isinstance(i, str) for i in x) for x in (train, test)):
        raise ValueError("invalid split candidates")
    if len(train) != len(set(train)) or len(test) != len(set(test)) or set(train) & set(test) or set(train) | set(test) != ids:
        raise ValueError("invalid split candidates")
    query_ids: set[str] = set()
    for row in value["query_results"] if isinstance(value["query_results"], list) else ():
        if (not isinstance(row, dict) or set(row) != {"query_id", "family", "cost", "candidate_ids"} or
                not isinstance(row.get("query_id"), str) or not _OPAQUE.fullmatch(row["query_id"]) or row["query_id"] in query_ids or
                not isinstance(row.get("family"), str) or not _OPAQUE.fullmatch(row["family"]) or isinstance(row.get("cost"), bool) or
                not isinstance(row.get("cost"), int) or row["cost"] < 0 or
                not isinstance(row.get("candidate_ids"), list) or not all(isinstance(x, str) for x in row["candidate_ids"]) or
                len(row["candidate_ids"]) != len(set(row["candidate_ids"])) or not set(row["candidate_ids"]) <= ids):
            raise ValueError("invalid query result")
        query_ids.add(row["query_id"])
    if not query_ids:
        raise ValueError("query results required")
    schedules = value["schedules"]
    if not isinstance(schedules, dict) or set(schedules) != {"baseline", "proposed"}:
        raise ValueError("invalid schedules")
    for stream in schedules.values():
        if not isinstance(stream, list) or not all(isinstance(x, str) for x in stream) or len(stream) != len(set(stream)) or set(stream) != query_ids:
            raise ValueError("schedules must order the same declared stream")
    budgets = value["budgets"]
    if not isinstance(budgets, list) or not budgets or any(isinstance(x, bool) or not isinstance(x, int) or x < 0 for x in budgets) or budgets != sorted(set(budgets)):
        raise ValueError("invalid budgets")
    return value


def _metrics(selected: set[str], labels: Mapping[str, str], eligible: set[str]) -> dict[str, Any]:
    chosen = selected & eligible
    relevant = sum(labels[x] == "relevant" for x in chosen)
    false_positive = sum(labels[x] == "known_false_positive" for x in chosen)
    unknown = sum(labels[x] == "unlabeled_unknown" for x in chosen)
    relevant_total = sum(labels[x] == "relevant" for x in eligible)
    known_denominator = relevant + false_positive
    return {"selected_unique": len(chosen), "relevant_found": relevant,
            "relevant_total": relevant_total,
            "recall_at_budget": (relevant / relevant_total if relevant_total else None),
            "known_false_positive": false_positive,
            "known_precision_denominator": known_denominator,
            "precision_on_known_labels": (relevant / known_denominator if known_denominator else None),
            "unlabeled_unknown": unknown}


def evaluate_discovery(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    data = load_evaluation(source)
    labels = {x["candidate_id"]: x["label"] for x in data["candidates"]}
    candidate_families = {x["candidate_id"]: set(x["families"]) for x in data["candidates"]}
    heldout = set(data["splits"]["test"])
    queries = {x["query_id"]: x for x in data["query_results"]}
    families = sorted({x["family"] for x in data["query_results"]})
    results: dict[str, list[dict[str, Any]]] = {}
    for schedule_name, order in data["schedules"].items():
        rows = []
        for maximum in data["budgets"]:
            used = 0
            selected: set[str] = set()
            family_selected = {family: set() for family in families}
            executed: list[str] = []
            for query_id in order:
                query = queries[query_id]
                if used + query["cost"] > maximum:
                    break
                used += query["cost"]
                executed.append(query_id)
                values = set(query["candidate_ids"])
                selected |= values
                family_selected[query["family"]] |= values
            per_family = {}
            for family in families:
                eligible = {candidate for candidate in heldout if family in candidate_families[candidate]}
                per_family[family] = _metrics(family_selected[family], labels, eligible)
            rows.append({"budget": maximum, "actual_cost": used, "executed_query_ids": executed,
                         "overall": _metrics(selected, labels, heldout), "families": per_family})
        results[schedule_name] = rows
    return {"version": 1, "dataset_id": data["dataset_card"]["dataset_id"],
            "input_sha256": _canonical_digest(data), "synthetic": data["dataset_card"]["synthetic"],
            "reproducibility": {"candidate_ids_fixed_before_runs": True, "test_labels_not_used_for_tuning": True,
                                "same_declared_query_stream": True, "schedule_policy": "stop_at_first_unaffordable",
                                "split_grouping": data["dataset_card"]["split_grouping"], "blind_split_verified": False,
                                "schedule_optimality_claimed": False},
            "evaluation_split": "test", "results": results,
            "limitations": list(data["dataset_card"]["limitations"])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate two fixed discovery schedules offline")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = evaluate_discovery(args.input)
        if Path(args.input).resolve() == Path(args.output).resolve(): raise ValueError("input and output collide")
        _exclusive_json(Path(args.output),result)
        print(json.dumps({"dataset_id": result["dataset_id"], "input_sha256": result["input_sha256"]}))
        return 0
    except (ValueError, OSError, json.JSONDecodeError):
        print(json.dumps({"error": "discovery_evaluation_failed"}))
        return 2
