#!/usr/bin/env python3
"""Validate the versioned KAN-118 policy pack without scanner dependencies."""

from __future__ import annotations

import json
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "policy-pack" / "v1"
VALID = PACK / "fixtures" / "valid"
INVALID = PACK / "fixtures" / "invalid"
CATALOG = PACK / "catalog" / "cases.json"
CATALOG_NEGATIVE = PACK / "catalog" / "negative-mutations.json"
INTEGRITY = PACK / "integrity" / "cases.json"
PLAN = ROOT / "docs" / "KAN-118-adversarial-test-plan.md"
EXPECTED_CASE_COUNT = 92

CASE_KEYS = {"schema_version", "id", "title", "category", "observed", "expected", "evidence"}
OBSERVED_KEYS = {"policy_status", "scanner_status", "origin", "risk_type", "severity", "confidence", "exploitable", "fix_available", "bypass_attempt"}
EXPECTED_KEYS = {"decision", "exit_code", "pr_outcome", "publish_allowed", "reason_code"}
EVIDENCE_KEYS = {"redacted", "required_fields"}
CATEGORIES = {"policy", "integrity", "gitleaks", "semgrep", "trivy-filesystem", "trivy-image", "developer-experience"}
POLICY_STATUSES = {"valid", "invalid", "expired", "corrupt"}
SCANNER_STATUSES = {"ok", "timeout", "outage", "internal_error"}
ORIGINS = {"none", "baseline", "introduced"}
RISK_TYPES = {"none", "vulnerability", "injection", "secret", "provenance"}
SEVERITIES = {"none", "low", "medium", "high", "critical"}
CONFIDENCES = {"none", "low", "high"}
EVIDENCE_FIELDS = {"case_id", "repository", "base_sha", "head_sha", "workflow_sha", "scanner_version", "decision", "reason", "remediation"}
CATALOG_KEYS = {"id", "title", "plan_ref", "status", "implementation", "expected_evidence", "evidence"}
STATUS_KEYS = {"cataloged", "implemented", "validated", "validation_scope"}
IMPLEMENTATION_KEYS = {"type", "path"}
CATALOG_EVIDENCE_REQUIRED_KEYS = {"type", "url", "commit_sha", "result", "scope"}
CATALOG_EVIDENCE_OPTIONAL_KEYS = {
    "job_url",
    "workflow_sha",
    "expected_state",
    "actual_state",
    "artifact_id",
    "control_outcome",
}
GITHUB_POC_PREFIX = "https://github.com/Sul4m/devsecops-poc-"
PLAN_PREFIX_MATRIX = {
    "POL": "Matriz A — Política y Shape Up",
    "INT": "Matriz B — Integridad y bypass del pipeline",
    "GL": "Matriz C — Gitleaks",
    "SG": "Matriz D — Semgrep y reglas propias",
    "TF": "Matriz E — Trivy filesystem/SCA",
    "TI": "Matriz F — Trivy imagen",
    "DX": "Matriz G — Tests, build y experiencia del desarrollador",
}


class ValidationError(Exception):
    """A deterministic validation failure with a stable category."""


def fail(category: str, message: str) -> None:
    raise ValidationError(f"[{category}] {message}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail("SCHEMA", f"{path.relative_to(ROOT)} is not valid JSON: {exc}")


def require_exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("SCHEMA", f"{context} must be an object")
    actual = set(value)
    if actual != expected:
        fail("SCHEMA", f"{context} keys differ: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")
    return value


def validate_shape(case: Any, source: Path) -> dict[str, Any]:
    context = str(source.relative_to(ROOT))
    case = require_exact_keys(case, CASE_KEYS, context)
    if case["schema_version"] != "1.0.0":
        fail("SCHEMA", f"{context} has unsupported schema_version")
    if not isinstance(case["id"], str) or not re.fullmatch(r"[A-Z]{2,3}-\d{2}", case["id"]):
        fail("SCHEMA", f"{context} has invalid case id")
    if not isinstance(case["title"], str) or not case["title"].strip():
        fail("SCHEMA", f"{context} title must be non-empty")
    if case["category"] not in CATEGORIES:
        fail("SCHEMA", f"{context} has unknown category")

    observed = require_exact_keys(case["observed"], OBSERVED_KEYS, f"{context}.observed")
    enum_fields = {
        "policy_status": POLICY_STATUSES,
        "scanner_status": SCANNER_STATUSES,
        "origin": ORIGINS,
        "risk_type": RISK_TYPES,
        "severity": SEVERITIES,
        "confidence": CONFIDENCES,
    }
    for field, allowed in enum_fields.items():
        if observed[field] not in allowed:
            fail("SCHEMA", f"{context}.observed.{field} has unknown value")
    for field in ("exploitable", "fix_available", "bypass_attempt"):
        if type(observed[field]) is not bool:
            fail("SCHEMA", f"{context}.observed.{field} must be boolean")

    expected = require_exact_keys(case["expected"], EXPECTED_KEYS, f"{context}.expected")
    if expected["decision"] not in {"PASS", "WARN", "BLOCK", "POLICY_ERROR", "SCANNER_ERROR"}:
        fail("SCHEMA", f"{context}.expected.decision has unknown value")
    if type(expected["exit_code"]) is not int or type(expected["publish_allowed"]) is not bool:
        fail("SCHEMA", f"{context}.expected has invalid scalar types")
    if expected["pr_outcome"] not in {"green", "red"}:
        fail("SCHEMA", f"{context}.expected.pr_outcome has unknown value")
    if not isinstance(expected["reason_code"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]+", expected["reason_code"]):
        fail("SCHEMA", f"{context}.expected.reason_code is invalid")

    evidence = require_exact_keys(case["evidence"], EVIDENCE_KEYS, f"{context}.evidence")
    if evidence["redacted"] is not True:
        fail("SAFETY", f"{context} requires redacted evidence")
    fields = evidence["required_fields"]
    if not isinstance(fields, list) or not fields or len(fields) != len(set(fields)) or not set(fields) <= EVIDENCE_FIELDS:
        fail("SCHEMA", f"{context}.evidence.required_fields is invalid")
    return case


def decide(observed: dict[str, Any]) -> tuple[str, str]:
    if observed["policy_status"] != "valid":
        return "POLICY_ERROR", "POLICY_NOT_VALID"
    if observed["scanner_status"] != "ok":
        return "SCANNER_ERROR", "SCANNER_UNAVAILABLE"
    if observed["bypass_attempt"]:
        return "BLOCK", "CONTROL_BYPASS"
    if observed["origin"] == "baseline":
        return "WARN", "BASELINE_DEBT"
    if observed["origin"] == "introduced" and observed["risk_type"] in {"secret", "provenance"}:
        reason = "CONFIRMED_SECRET" if observed["risk_type"] == "secret" else "INVALID_PROVENANCE"
        return "BLOCK", reason
    if (
        observed["origin"] == "introduced"
        and observed["severity"] in {"high", "critical"}
        and observed["confidence"] == "high"
        and observed["exploitable"]
        and (observed["fix_available"] or observed["severity"] == "critical")
    ):
        return "BLOCK", "ACTIONABLE_REGRESSION"
    if observed["origin"] == "introduced":
        return "WARN", "UNCONFIRMED_RISK"
    return "PASS", "NO_ACTIONABLE_RISK"


def validate_decision(case: dict[str, Any], policy: dict[str, Any], source: Path) -> None:
    decision, reason = decide(case["observed"])
    expected = case["expected"]
    contract = policy["taxonomy"][decision]
    actual = {
        "decision": decision,
        "reason_code": reason,
        "exit_code": contract["exit_code"],
        "pr_outcome": contract["pr_outcome"],
        "publish_allowed": contract["publish_allowed"],
    }
    if expected != actual:
        fail("DECISION", f"{source.relative_to(ROOT)} expected={expected}, evaluated={actual}")


def validate_policy(policy: Any) -> dict[str, Any]:
    policy = require_exact_keys(policy, {"schema_version", "policy_version", "enforcement_scope", "taxonomy", "precedence"}, "policy.json")
    if policy["schema_version"] != "1.0.0" or policy["policy_version"] != "1.0.0":
        fail("SCHEMA", "policy.json version is unsupported")
    if policy["enforcement_scope"] != "job_conclusion_only":
        fail("SCHEMA", "policy.json must not claim merge enforcement")
    states = {"PASS", "WARN", "BLOCK", "POLICY_ERROR", "SCANNER_ERROR"}
    if set(policy["taxonomy"]) != states or set(policy["precedence"]) != states:
        fail("SCHEMA", "policy.json taxonomy is incomplete")
    expected_contract = {
        "PASS": {"exit_code": 0, "pr_outcome": "green", "publish_allowed": True},
        "WARN": {"exit_code": 0, "pr_outcome": "green", "publish_allowed": True},
        "BLOCK": {"exit_code": 10, "pr_outcome": "red", "publish_allowed": False},
        "POLICY_ERROR": {"exit_code": 20, "pr_outcome": "red", "publish_allowed": False},
        "SCANNER_ERROR": {"exit_code": 30, "pr_outcome": "red", "publish_allowed": False},
    }
    if policy["taxonomy"] != expected_contract:
        fail("SCHEMA", "policy.json exit behavior differs from the approved taxonomy")
    return policy


def plan_case_ids() -> set[str]:
    ids = re.findall(r"^\| ((?:POL|INT|GL|SG|TF|TI|DX)-\d{2}) \|", PLAN.read_text(encoding="utf-8"), re.MULTILINE)
    if len(ids) != len(set(ids)):
        fail("CATALOG", "adversarial plan contains duplicate case IDs")
    if len(ids) != EXPECTED_CASE_COUNT:
        fail("CATALOG", f"adversarial plan must contain {EXPECTED_CASE_COUNT} cases, found {len(ids)}")
    return set(ids)


def validate_catalog(catalog: Any, plan_ids: set[str]) -> None:
    catalog = require_exact_keys(catalog, {"schema_version", "plan_document", "cases"}, "catalog/cases.json")
    if catalog["schema_version"] != "1.0.0" or catalog["plan_document"] != str(PLAN.relative_to(ROOT)):
        fail("CATALOG", "catalog version or plan_document is invalid")
    cases = catalog["cases"]
    if not isinstance(cases, list):
        fail("CATALOG", "catalog cases must be an array")
    ids = [case.get("id") for case in cases if isinstance(case, dict)]
    if len(ids) != len(set(ids)):
        fail("CATALOG", "catalog contains duplicate case IDs")
    actual_ids = set(ids)
    if actual_ids != plan_ids:
        fail("CATALOG", f"catalog differs from plan: missing={sorted(plan_ids - actual_ids)}, unknown={sorted(actual_ids - plan_ids)}")

    for index, value in enumerate(cases):
        case = require_exact_keys(value, CATALOG_KEYS, f"catalog.cases[{index}]")
        case_id = case["id"]
        prefix = case_id.split("-", 1)[0]
        plan_ref = require_exact_keys(case["plan_ref"], {"document", "matrix", "case_id"}, f"catalog.{case_id}.plan_ref")
        if plan_ref != {"document": str(PLAN.relative_to(ROOT)), "matrix": PLAN_PREFIX_MATRIX[prefix], "case_id": case_id}:
            fail("CATALOG", f"{case_id} has an ambiguous plan reference")
        status = require_exact_keys(case["status"], STATUS_KEYS, f"catalog.{case_id}.status")
        if any(type(status[field]) is not bool for field in ("cataloged", "implemented", "validated")):
            fail("CATALOG", f"{case_id} lifecycle flags must be boolean")
        if not status["cataloged"] or status["validated"] and not status["implemented"]:
            fail("CATALOG", f"{case_id} lifecycle ordering is invalid")
        if status["validation_scope"] not in {"none", "contract", "platform"}:
            fail("CATALOG", f"{case_id} validation_scope is invalid")
        implementation = require_exact_keys(case["implementation"], IMPLEMENTATION_KEYS, f"catalog.{case_id}.implementation")
        if status["implemented"]:
            is_local_fixture = (
                implementation["type"] != "github_pr_fixture"
                and implementation["path"]
                and (ROOT / implementation["path"]).is_file()
            )
            is_github_fixture = (
                implementation["type"] == "github_pr_fixture"
                and isinstance(implementation["path"], str)
                and re.fullmatch(rf"{re.escape(GITHUB_POC_PREFIX)}[a-z0-9-]+/pull/\d+", implementation["path"])
            )
            if not is_local_fixture and not is_github_fixture:
                fail("CATALOG", f"{case_id} is implemented without an existing implementation path")
        elif implementation != {"type": None, "path": None}:
            fail("CATALOG", f"{case_id} has implementation metadata but is not implemented")
        if not isinstance(case["expected_evidence"], list) or not case["expected_evidence"]:
            fail("CATALOG", f"{case_id} expected_evidence is empty")
        if not isinstance(case["evidence"], list):
            fail("CATALOG", f"{case_id} evidence must be an array")
        if status["validated"]:
            if not case["evidence"] or status["validation_scope"] == "none":
                fail("CATALOG", f"{case_id} is declared validated without evidence")
            for evidence in case["evidence"]:
                if not isinstance(evidence, dict):
                    fail("CATALOG", f"{case_id} evidence must be an object")
                evidence_keys = set(evidence)
                missing = CATALOG_EVIDENCE_REQUIRED_KEYS - evidence_keys
                extra = evidence_keys - CATALOG_EVIDENCE_REQUIRED_KEYS - CATALOG_EVIDENCE_OPTIONAL_KEYS
                if missing or extra:
                    fail("CATALOG", f"{case_id} evidence keys differ: missing={sorted(missing)}, extra={sorted(extra)}")
                if evidence["type"] != "github_actions" or evidence["result"] != "passed" or evidence["scope"] not in {"contract", "platform"}:
                    fail("CATALOG", f"{case_id} evidence has unsupported semantics")
                if evidence["scope"] != status["validation_scope"]:
                    fail("CATALOG", f"{case_id} evidence scope differs from validation scope")
                if not re.fullmatch(r"[0-9a-f]{40}", evidence["commit_sha"]):
                    fail("CATALOG", f"{case_id} evidence commit is not immutable")
                if not re.fullmatch(rf"{re.escape(GITHUB_POC_PREFIX)}[a-z0-9-]+/actions/runs/\d+", evidence["url"]):
                    fail("CATALOG", f"{case_id} evidence URL is not a GitHub Actions run")
                if "job_url" in evidence and not re.fullmatch(
                    rf"{re.escape(evidence['url'])}/job/\d+", evidence["job_url"]
                ):
                    fail("CATALOG", f"{case_id} evidence job URL does not belong to its run")
                if "workflow_sha" in evidence and not re.fullmatch(r"[0-9a-f]{40}", evidence["workflow_sha"]):
                    fail("CATALOG", f"{case_id} workflow SHA is not immutable")
                if ("expected_state" in evidence) != ("actual_state" in evidence):
                    fail("CATALOG", f"{case_id} evidence must include expected and actual state together")
                if evidence.get("expected_state") != evidence.get("actual_state"):
                    fail("CATALOG", f"{case_id} expected and actual state differ")
                if "artifact_id" in evidence and not str(evidence["artifact_id"]).isdigit():
                    fail("CATALOG", f"{case_id} artifact ID is invalid")
                if "control_outcome" in evidence and evidence["control_outcome"] not in {
                    "passed",
                    "failed",
                    "unsupported",
                }:
                    fail("CATALOG", f"{case_id} control outcome is invalid")
        elif case["evidence"] or status["validation_scope"] != "none":
            fail("CATALOG", f"{case_id} has validation evidence without validated status")


def validate_catalog_rejections(catalog: dict[str, Any], plan_ids: set[str]) -> None:
    negative = load_json(CATALOG_NEGATIVE)
    negative = require_exact_keys(negative, {"schema_version", "mutations"}, "catalog/negative-mutations.json")
    if negative["schema_version"] != "1.0.0" or not isinstance(negative["mutations"], list):
        fail("CATALOG", "catalog rejection manifest is invalid")
    for mutation in negative["mutations"]:
        mutation = require_exact_keys(mutation, {"id", "operation", "case_id", "expected_marker"}, "catalog mutation")
        candidate = deepcopy(catalog)
        matches = [case for case in candidate["cases"] if case["id"] == mutation["case_id"]]
        operation = mutation["operation"]
        if operation == "remove":
            candidate["cases"] = [case for case in candidate["cases"] if case["id"] != mutation["case_id"]]
        elif operation == "duplicate" and matches:
            candidate["cases"].append(deepcopy(matches[0]))
        elif operation == "add_unknown":
            sample = deepcopy(candidate["cases"][0])
            sample["id"] = mutation["case_id"]
            sample["plan_ref"]["case_id"] = mutation["case_id"]
            candidate["cases"].append(sample)
        elif operation == "clear_evidence" and matches:
            matches[0]["evidence"] = []
        else:
            fail("CATALOG", f"unsupported or inapplicable catalog mutation {mutation['id']}")
        try:
            validate_catalog(candidate, plan_ids)
        except ValidationError as exc:
            if mutation["expected_marker"] not in str(exc):
                fail("CATALOG", f"mutation {mutation['id']} failed with unexpected category: {exc}")
        else:
            fail("CATALOG", f"mutation {mutation['id']} was accepted")


def evaluate_integrity(case: dict[str, Any]) -> tuple[str, str]:
    check = case["check"]
    snapshot = case["snapshot"]
    actual = snapshot["actual"]
    required = snapshot["required"]
    if check in {"required_job", "trigger_present"}:
        return ("PASS", "CONTRACT_PRESENT") if required in actual else ("BLOCK", "REQUIRED_JOB_MISSING" if check == "required_job" else "REQUIRED_TRIGGER_MISSING")
    if check == "approved_ref":
        approved = actual in required and isinstance(actual, str) and re.fullmatch(r"[0-9a-f]{40}", actual)
        return ("PASS", "WORKFLOW_REF_APPROVED") if approved else ("BLOCK", "WORKFLOW_REF_NOT_APPROVED")
    if check == "must_be_false":
        return ("PASS", "NO_BYPASS") if actual is required is False else ("BLOCK", "CONTROL_BYPASS")
    if check == "permissions_subset":
        return ("PASS", "LEAST_PRIVILEGE") if set(actual) <= set(required) else ("BLOCK", "EXCESSIVE_PERMISSIONS")
    if check == "trusted_source":
        reason = "UNTRUSTED_BASELINE" if required == "base" else "UNTRUSTED_POLICY"
        return ("PASS", "TRUSTED_SOURCE") if actual == required else ("BLOCK", reason)
    if check == "artifact_status":
        return ("PASS", "ARTIFACT_VALID") if actual == required else ("POLICY_ERROR", "ARTIFACT_INVALID")
    if check == "artifact_binding":
        return ("PASS", "ARTIFACT_BOUND") if actual == required else ("BLOCK", "ARTIFACT_BINDING_MISMATCH")
    if check == "reproducible_value":
        return ("PASS", "POLICY_REPRODUCIBLE") if actual == required else ("POLICY_ERROR", "POLICY_NOT_REPRODUCIBLE")
    if check == "runtime_compatibility":
        return ("PASS", "ACTION_RUNTIME_SUPPORTED") if actual in required else ("SCANNER_ERROR", "ACTION_RUNTIME_UNSUPPORTED")
    if check == "fork_permissions":
        return ("PASS", "FORK_LEAST_PRIVILEGE") if actual == required else ("BLOCK", "FORK_PRIVILEGE_ESCALATION")
    fail("INTEGRITY", f"{case['id']} uses unknown check {check}")


def validate_integrity_cases(value: Any) -> None:
    value = require_exact_keys(value, {"schema_version", "cases"}, "integrity/cases.json")
    if value["schema_version"] != "1.0.0" or not isinstance(value["cases"], list):
        fail("INTEGRITY", "integrity case pack is invalid")
    ids: list[str] = []
    for index, item in enumerate(value["cases"]):
        case = require_exact_keys(item, {"id", "title", "check", "snapshot", "expected", "limits"}, f"integrity.cases[{index}]")
        if not re.fullmatch(r"INT-\d{2}", case["id"]):
            fail("INTEGRITY", "integrity case ID is invalid")
        ids.append(case["id"])
        require_exact_keys(case["snapshot"], {"actual", "required"}, f"integrity.{case['id']}.snapshot")
        expected = require_exact_keys(case["expected"], {"decision", "reason_code"}, f"integrity.{case['id']}.expected")
        limits = require_exact_keys(case["limits"], {"validation_scope", "platform_evidence_required"}, f"integrity.{case['id']}.limits")
        if limits["validation_scope"] != "contract_snapshot" or type(limits["platform_evidence_required"]) is not bool:
            fail("INTEGRITY", f"{case['id']} must declare contract_snapshot limits")
        actual = evaluate_integrity(case)
        if expected != {"decision": actual[0], "reason_code": actual[1]}:
            fail("INTEGRITY", f"{case['id']} expected={expected}, evaluated={actual}")
    expected_ids = {f"INT-{number:02d}" for number in range(1, 15)}
    if len(ids) != len(set(ids)) or set(ids) != expected_ids:
        fail("INTEGRITY", f"integrity slice differs: missing={sorted(expected_ids - set(ids))}, unknown={sorted(set(ids) - expected_ids)}")


def main() -> int:
    policy = validate_policy(load_json(PACK / "policy.json"))
    schema = load_json(PACK / "schema" / "case.schema.json")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("SCHEMA", "case schema must use JSON Schema 2020-12")
    catalog_schema = load_json(PACK / "schema" / "catalog.schema.json")
    if catalog_schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("SCHEMA", "catalog schema must use JSON Schema 2020-12")

    plan_ids = plan_case_ids()
    catalog = load_json(CATALOG)
    validate_catalog(catalog, plan_ids)
    validate_catalog_rejections(catalog, plan_ids)
    validate_integrity_cases(load_json(INTEGRITY))

    valid_files = sorted(VALID.glob("*.json"))
    if not valid_files:
        fail("SCHEMA", "no valid fixtures found")
    seen: set[str] = set()
    covered: set[str] = set()
    for source in valid_files:
        case = validate_shape(load_json(source), source)
        if case["id"] in seen:
            fail("SCHEMA", f"duplicate case id {case['id']}")
        seen.add(case["id"])
        covered.add(case["expected"]["decision"])
        validate_decision(case, policy, source)
    required_states = set(policy["taxonomy"])
    if covered != required_states:
        fail("SCHEMA", f"taxonomy coverage differs: missing={sorted(required_states - covered)}")

    manifest = load_json(INVALID / "manifest.json")
    if not isinstance(manifest, dict) or not manifest:
        fail("SCHEMA", "invalid fixture manifest must be a non-empty object")
    for name, expected_marker in sorted(manifest.items()):
        source = INVALID / name
        try:
            case = validate_shape(load_json(source), source)
            validate_decision(case, policy, source)
        except ValidationError as exc:
            if expected_marker not in str(exc):
                fail("SCHEMA", f"{name} failed with {exc}, expected {expected_marker}")
        else:
            fail("SCHEMA", f"negative fixture {name} was accepted")

    statuses = {"cataloged": 0, "implemented": 0, "validated": 0}
    for case in catalog["cases"]:
        for status in statuses:
            statuses[status] += int(case["status"][status])
    print(
        f"policy-pack v{policy['policy_version']}: "
        f"catalog={statuses}, integrity=14 contract snapshots, "
        f"decision_fixtures={len(valid_files)}, rejection_cases={len(manifest)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
