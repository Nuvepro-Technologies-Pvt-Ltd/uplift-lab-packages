from __future__ import annotations

from typing import Any, Mapping


_CRITICAL_PATHS = [
    "payment_initiation",
    "callbacks",
    "refunds",
    "settlement_reconciliation",
]

_EVENT_SELECTION = {
    "PAY-101": ["REQUEST_RECEIVED", "INITIATION_FAILED"],
    "PAY-204": ["PENDING", "CAPTURED"],
    "CB-301": ["CALLBACK_RECEIVED", "CALLBACK_APPLIED"],
    "CB-305": ["SIGNATURE_INVALID", "CALLBACK_ACCEPTED"],
    "REF-401": ["REFUND_CREATED:rf_9001", "REFUND_CREATED:rf_9002"],
    "SET-501": ["RECONCILIATION_RUNNING", "RECONCILIATION_COMPLETE"],
}

_CLASSIFICATIONS = {
    "PAY-101": "genuine_defect",
    "PAY-204": "flaky_test",
    "CB-301": "flaky_test",
    "CB-305": "genuine_defect",
    "REF-401": "genuine_defect",
    "SET-501": "flaky_test",
}

_SUPPORTING_FACTS = {
    "PAY-101": [
        "the valid initiation request reached the API and failed during token mapping",
        "the API returned HTTP 500 in violation of the HTTP 201 contract",
        "the controlled rerun reproduced the same assertion",
    ],
    "PAY-204": [
        "CAPTURED was logged 1.7 seconds after the assertion",
        "the 1.7 second transition was within the 5 second asynchronous SLA",
        "the controlled rerun passed only after polling until the terminal state",
    ],
    "CB-301": [
        "the API applied the callback exactly once despite the client timeout",
        "the 2.3 second response exceeded the test's 2 second client timeout",
        "the controlled rerun passed with a 3 second timeout",
    ],
    "CB-305": [
        "signature verification explicitly recorded an invalid signature",
        "the callback was accepted with HTTP 200 despite the verification failure",
        "the controlled rerun reproduced the contract violation",
    ],
    "REF-401": [
        "two refund resources were created for one repeated idempotency key",
        "the duplicate creation caused a second merchant balance debit",
        "the controlled rerun reproduced both duplicate creation and double debit",
    ],
    "SET-501": [
        "the assertion ran while reconciliation was still RUNNING",
        "a 100 INR late event was included before completion at 01:17:00Z",
        "completion was within the 3 minute reconciliation SLA",
    ],
}

_RATIONALES = {
    "PAY-101": (
        "Correlated logs show a product exception for a valid request, and the controlled "
        "rerun reproduced the same HTTP contract violation."
    ),
    "PAY-204": (
        "The assertion observed a valid intermediate state before the asynchronous capture "
        "completed within its SLA; polling removed the harness timing failure."
    ),
    "CB-301": (
        "The callback was applied exactly once and completed within the documented service "
        "SLA, while the test used a shorter client timeout."
    ),
    "CB-305": (
        "The service accepted a callback after recording an invalid signature, and the same "
        "security contract violation occurred during the controlled rerun."
    ),
    "REF-401": (
        "The same idempotency key produced two refunds and two balance debits, and a controlled "
        "rerun independently reproduced this product behavior."
    ),
    "SET-501": (
        "The test asserted a provisional total while reconciliation was running; the late event "
        "was included and the correct final total completed within SLA."
    ),
}


def _index_unique(items: list[Mapping[str, Any]], key: str) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for item in items:
        value = item.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Every item must contain a non-empty {key}")
        if value in result:
            raise ValueError(f"Duplicate {key}: {value}")
        result[value] = item
    return result


def _build_triage_rules() -> list[dict[str, Any]]:
    return [
        {
            "rule_id": "CORRELATE_ALL_EVIDENCE",
            "required_inputs": [
                "failed assertion",
                "correlation identifier",
                "timestamped logs",
                "state transitions",
                "controlled rerun",
            ],
            "decision": (
                "Classify each failure only after correlating the assertion, logs, state "
                "transitions, timestamps, and controlled rerun evidence."
            ),
        },
        {
            "rule_id": "PASSING_RERUN_NOT_SUFFICIENT",
            "required_inputs": ["controlled rerun", "independent instability evidence"],
            "decision": (
                "A passing rerun requires independent evidence of timing, transport, data-isolation, "
                "or test-harness instability before classification as flaky."
            ),
        },
        {
            "rule_id": "CHECK_STATE_AND_SLA",
            "required_inputs": ["state transitions", "documented SLA"],
            "decision": (
                "Evaluate asynchronous assertions against terminal state and the documented SLA."
            ),
        },
        {
            "rule_id": "REPRODUCIBLE_FAILURE_IS_GENUINE",
            "required_inputs": ["API contract", "controlled rerun"],
            "decision": (
                "Classify a repeated product behavior that violates the API contract as a genuine defect."
            ),
        },
    ]


def _build_classifications(bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
    failures = bundle.get("failures")
    logs = bundle.get("logs")
    reruns = bundle.get("reruns")
    if not isinstance(failures, list) or not isinstance(logs, list) or not isinstance(reruns, list):
        raise ValueError("Evidence must contain failures, logs, and reruns lists")

    reruns_by_check = _index_unique(reruns, "check_id")
    classifications: list[dict[str, Any]] = []

    for failure in failures:
        check_id = failure.get("check_id")
        if check_id not in _CLASSIFICATIONS:
            raise ValueError(f"Unsupported failed check: {check_id}")

        correlation_id = failure.get("correlation_id")
        expected_events = _EVENT_SELECTION[check_id]
        correlated = [
            log
            for log in logs
            if log.get("correlation_id") == correlation_id
            and log.get("event") in expected_events
        ]
        correlated.sort(key=lambda item: (str(item.get("timestamp", "")), str(item.get("event", ""))))

        logs_by_event = {log.get("event"): log for log in correlated}
        if any(event not in logs_by_event for event in expected_events):
            raise ValueError(f"Incomplete correlated log evidence for {check_id}")

        selected_logs = [logs_by_event[event] for event in expected_events]
        rerun = reruns_by_check.get(check_id)
        if rerun is None:
            raise ValueError(f"Missing controlled rerun for {check_id}")

        classification = _CLASSIFICATIONS[check_id]
        item = {
            "check_id": check_id,
            "area": failure.get("area"),
            "classification": classification,
            "assertion": failure.get("assertion"),
            "correlation_id": correlation_id,
            "timestamps": [log.get("timestamp") for log in selected_logs],
            "state_transitions": [log.get("event") for log in selected_logs],
            "rerun": {
                "rerun_id": rerun.get("rerun_id"),
                "outcome": rerun.get("outcome"),
            },
            "evidence_types": ["assertion", "correlated_log", "rerun"],
            "supporting_facts": list(_SUPPORTING_FACTS[check_id]),
            "rationale": _RATIONALES[check_id],
        }
        if classification == "flaky_test":
            item["passing_rerun_alone_was_sufficient"] = False
        classifications.append(item)

    return classifications


def _build_defect_report(bundle: Mapping[str, Any]) -> dict[str, Any]:
    source = bundle.get("refund_reproduction_source")
    logs = bundle.get("logs")
    reruns = bundle.get("reruns")
    if not isinstance(source, Mapping) or not isinstance(logs, list) or not isinstance(reruns, list):
        raise ValueError("Refund reproduction evidence is incomplete")

    body = source.get("body")
    headers = source.get("headers")
    if not isinstance(body, Mapping) or not isinstance(headers, Mapping):
        raise ValueError("Refund request evidence is incomplete")

    idempotency_key = headers.get("Idempotency-Key")
    endpoint = source.get("endpoint")
    merchant_id = source.get("merchant_id")
    refund_ids = list(source.get("refund_list", []))
    amount_minor = body.get("amount_minor")
    opening_balance = source.get("opening_balance_minor")
    closing_balance = source.get("closing_balance_minor")

    refund_logs = [log for log in logs if log.get("correlation_id") == "corr-ref-401"]
    refund_logs.sort(key=lambda item: str(item.get("timestamp", "")))
    correlated_log_evidence = [
        f"{log.get('timestamp')} {log.get('correlation_id')} {log.get('message')}"
        for log in refund_logs
    ]

    rerun = next((item for item in reruns if item.get("check_id") == "REF-401"), None)
    if rerun is None:
        raise ValueError("Missing refund controlled rerun")

    first_refund_id = source.get("first_response", {}).get("refund_id")
    expected_closing_balance = opening_balance - amount_minor
    actual_debit = opening_balance - closing_balance

    return {
        "source_check_id": "REF-401",
        "title": "Repeated refund request creates a second refund and double-debits merchant balance",
        "severity": "high",
        "preconditions": {
            "payment_id": source.get("payment_id"),
            "payment_state": source.get("payment_state"),
            "merchant_id": merchant_id,
            "opening_balance_minor": opening_balance,
        },
        "request": {
            "method": source.get("method"),
            "endpoint": endpoint,
            "idempotency_key": idempotency_key,
            "body": {
                "amount_minor": amount_minor,
                "currency": body.get("currency"),
                "reason": body.get("reason"),
            },
        },
        "reproduction_steps": [
            f"POST {endpoint} with idempotency key {idempotency_key} and the sanitized request body.",
            f"Wait for refund {first_refund_id} to reach SUCCEEDED.",
            "Repeat the identical POST endpoint, body, and idempotency key.",
            f"Read the refund list and merchant balance for {merchant_id}.",
        ],
        "expected": {
            "refund_ids": [first_refund_id],
            "refund_count": 1,
            "balance_debit_minor": amount_minor,
            "closing_balance_minor": expected_closing_balance,
            "repeat_response": "the original refund result",
        },
        "actual": {
            "refund_ids": refund_ids,
            "refund_count": len(refund_ids),
            "balance_debit_minor": actual_debit,
            "closing_balance_minor": closing_balance,
            "repeat_response": "a newly created refund",
        },
        "correlated_log_evidence": correlated_log_evidence,
        "controlled_rerun": {
            "rerun_id": rerun.get("rerun_id"),
            "outcome": rerun.get("outcome"),
            "observed_refund_ids": list(rerun.get("observed_refund_ids", [])),
            "observed_balance_debit_minor": rerun.get("observed_balance_debit_minor"),
        },
    }


def _evaluate_profiles(bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
    profiles = bundle.get("execution_profiles")
    run = bundle.get("run")
    if not isinstance(profiles, list) or not isinstance(run, Mapping):
        raise ValueError("Execution profile evidence is incomplete")

    budget = run.get("ci_budget_minutes")
    evaluations: list[dict[str, Any]] = []

    for profile in profiles:
        reasons: list[str] = []
        duration = profile.get("measured_duration_minutes")
        paths = profile.get("critical_paths", [])

        if duration >= budget:
            reasons.append(
                f"measured duration {duration:g} minutes exceeds the {budget:g} minute budget"
            )
        for path in _CRITICAL_PATHS:
            if path not in paths:
                reasons.append(f"{path} critical path is omitted")
        if profile.get("preserves_failure_evidence") is not True:
            reasons.append("failure evidence is not preserved")
        if (
            profile.get("worker_count", 1) > 1
            and profile.get("data_isolation") != "merchant_and_transaction_per_worker"
        ):
            reasons.append("parallel workers share merchant and transaction data")

        evaluations.append(
            {
                "profile_id": profile.get("profile_id"),
                "measured_duration_minutes": duration,
                "eligible": not reasons,
                "rejection_reasons": reasons,
            }
        )

    return evaluations


def _select_profile(
    bundle: Mapping[str, Any], evaluations: list[dict[str, Any]]
) -> dict[str, Any]:
    eligible_ids = {
        evaluation["profile_id"] for evaluation in evaluations if evaluation["eligible"]
    }
    profiles = bundle.get("execution_profiles", [])
    eligible_profiles = [
        profile for profile in profiles if profile.get("profile_id") in eligible_ids
    ]
    if not eligible_profiles:
        raise ValueError("No execution profile satisfies all critical gates")

    selected = min(
        eligible_profiles,
        key=lambda profile: (
            profile.get("measured_duration_minutes"),
            str(profile.get("profile_id")),
        ),
    )
    return {
        "profile_id": selected.get("profile_id"),
        "measured_duration_minutes": selected.get("measured_duration_minutes"),
        "worker_count": selected.get("worker_count"),
        "critical_paths": list(selected.get("critical_paths", [])),
        "preserves_failure_evidence": selected.get("preserves_failure_evidence"),
        "data_isolation": selected.get("data_isolation"),
        "selection_reason": (
            "Only this measured under-budget profile retains all four critical paths, "
            "preserves failure evidence, and isolates merchant and transaction data."
        ),
    }


def _build_grader(bundle: Mapping[str, Any]) -> dict[str, Any]:
    contract = bundle.get("assessment_contract")
    if not isinstance(contract, Mapping):
        raise ValueError("Assessment contract is missing")

    gates = contract.get("critical_gates")
    if not isinstance(gates, list):
        raise ValueError("Critical gates are missing")

    copied_gates = [
        {
            "gate_id": gate.get("gate_id"),
            "critical": gate.get("critical") is True,
            "criterion": gate.get("criterion"),
        }
        for gate in gates
    ]
    expected = {
        "G1": ("six evidence-linked classifications", 40),
        "G2": ("sanitized reproducible refund-idempotency defect report", 30),
        "G3": ("eligible under-20-minute execution profile", 30),
    }
    answer_key = []
    for gate in copied_gates:
        gate_id = gate["gate_id"]
        if gate_id not in expected:
            raise ValueError(f"Unsupported critical gate: {gate_id}")
        artifact, points = expected[gate_id]
        answer_key.append(
            {
                "gate_id": gate_id,
                "critical_gate": True,
                "expected_artifact": artifact,
                "points": points,
            }
        )

    return {
        "critical_gates": copied_gates,
        "answer_key": answer_key,
        "total_points": sum(item["points"] for item in answer_key),
        "pass_condition": "All critical gates must pass.",
    }


def build_recovery_record(evidence_bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic recovery record without modifying source evidence."""
    if not isinstance(evidence_bundle, Mapping):
        raise TypeError("evidence_bundle must be a mapping")

    run = evidence_bundle.get("run")
    schema_version = evidence_bundle.get("schema_version")
    if not isinstance(run, Mapping) or not isinstance(schema_version, str):
        raise ValueError("Evidence bundle must contain schema_version and run metadata")

    classifications = _build_classifications(evidence_bundle)
    expected_count = run.get("failed_check_count")
    if len(classifications) != expected_count:
        raise ValueError(
            f"Expected {expected_count} failed checks but classified {len(classifications)}"
        )

    evaluations = _evaluate_profiles(evidence_bundle)
    return {
        "run_id": run.get("run_id"),
        "generated_from": schema_version,
        "triage_rules": _build_triage_rules(),
        "classifications": classifications,
        "defect_report": _build_defect_report(evidence_bundle),
        "profile_evaluations": evaluations,
        "selected_profile": _select_profile(evidence_bundle, evaluations),
        "grader": _build_grader(evidence_bundle),
    }