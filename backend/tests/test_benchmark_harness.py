from __future__ import annotations

import pandas as pd

from backend.scripts.run_benchmark_harness import (
    _persist_file_dynamic_policy_artifacts,
    _resolve_dynamic_provider_run_label,
    _resolve_file_dynamic_runtime,
    _filter_sql_frame_by_scope,
    build_file_dynamic_policy_report,
    compute_binary_metrics,
    evaluate_file_dynamic_policy_gate,
    evaluate_regression_gate,
    evaluate_sql_heldout_gate,
    evaluate_sql_slice_gate,
)


def test_compute_binary_metrics_basic():
    metrics = compute_binary_metrics(
        y_true=[1, 1, 0, 0],
        y_pred=[1, 0, 1, 0],
        high_severity_flags=[True, True, False, False],
    ).as_dict()

    assert metrics["confusion_matrix"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_count"] == 1
    assert metrics["high_severity_miss_rate"] == 0.5


def test_regression_gate_detects_threshold_and_regression_failure():
    thresholds = {
        "domains": {
            "sql.analysis": {
                "min_precision": 0.7,
                "min_recall": 0.7,
                "min_f1": 0.7,
                "max_fpr": 0.2,
                "max_high_severity_miss_rate": 0.2,
            }
        },
        "regression": {
            "max_precision_drop": 0.05,
            "max_recall_drop": 0.05,
            "max_f1_drop": 0.05,
            "max_fpr_increase": 0.05,
            "max_high_severity_miss_rate_increase": 0.05,
        },
    }
    current = {
        "sql.analysis": {
            "precision": 0.6,
            "recall": 0.6,
            "f1": 0.6,
            "false_positive_rate": 0.3,
            "high_severity_miss_rate": 0.3,
        }
    }
    baseline = {
        "sql.analysis": {
            "precision": 0.9,
            "recall": 0.9,
            "f1": 0.9,
            "false_positive_rate": 0.1,
            "high_severity_miss_rate": 0.1,
        }
    }
    gate = evaluate_regression_gate(current_metrics=current, baseline_metrics=baseline, thresholds=thresholds)
    assert gate["passed"] is False
    assert len(gate["reasons"]) >= 3


def test_sql_slice_gate_applies_thresholds():
    thresholds = {
        "sql_slices": {
            "enforcement": {
                "severity_slice": {
                    "high_severity": {
                        "min_recall": 0.70,
                        "max_high_severity_miss_rate": 0.30,
                        "min_sample_count": 10,
                    }
                }
            }
        }
    }
    results = {
        "sql": {
            "slices": {
                "enforcement": {
                    "severity_slice": {
                        "high_severity": {
                            "confusion_matrix": {"tp": 6, "fp": 0, "tn": 0, "fn": 4},
                            "precision": 1.0,
                            "recall": 0.6,
                            "f1": 0.75,
                            "false_positive_rate": 0.0,
                            "high_severity_miss_rate": 0.4,
                            "sample_count": 10,
                        }
                    }
                }
            }
        }
    }
    gate = evaluate_sql_slice_gate(results=results, thresholds=thresholds)
    assert gate["passed"] is False
    assert any("sql.enforcement.severity_slice.high_severity" in reason for reason in gate["reasons"])


def test_sql_scope_filter_distinguishes_original_vs_held_out():
    frame = pd.DataFrame(
        [
            {"sample_id": "a", "benchmark_group": "tuning", "source_file": "sql_corpus_template.csv", "split": "train"},
            {"sample_id": "b", "benchmark_group": "regression", "source_file": "sql_online_weaklabels.csv", "split": "test"},
            {"sample_id": "c", "benchmark_group": "held_out_adversarial", "source_file": "sql_adversarial_heldout.csv", "split": "test"},
        ]
    )
    original = _filter_sql_frame_by_scope(frame, "original")
    held_out = _filter_sql_frame_by_scope(frame, "held_out")
    combined = _filter_sql_frame_by_scope(frame, "combined")
    assert set(original["sample_id"].tolist()) == {"a", "b"}
    assert set(held_out["sample_id"].tolist()) == {"c"}
    assert set(combined["sample_id"].tolist()) == {"a", "b", "c"}


def test_sql_heldout_gate_requires_minimum_quality():
    thresholds = {
        "sql_heldout": {
            "enforcement": {
                "min_sample_count": 20,
                "min_precision": 0.8,
                "min_recall": 0.6,
                "min_f1": 0.7,
                "max_fpr": 0.1,
                "max_high_severity_miss_rate": 0.4,
            }
        }
    }
    results = {
        "sql": {
            "held_out_only": {
                "sample_count": 30,
                "metrics": {
                    "enforcement": {
                        "confusion_matrix": {"tp": 10, "fp": 2, "tn": 8, "fn": 10},
                        "precision": 0.8333,
                        "recall": 0.5,
                        "f1": 0.625,
                        "false_positive_rate": 0.2,
                        "high_severity_miss_rate": 0.5,
                    }
                },
            }
        }
    }
    gate = evaluate_sql_heldout_gate(results=results, thresholds=thresholds)
    assert gate["passed"] is False
    assert any("sql.enforcement.held_out" in reason for reason in gate["reasons"])


def test_file_dynamic_policy_report_includes_request_and_state_accounting():
    predictions = [
        {
            "sample_id": "a",
            "label": 0,
            "file_family": "pdf",
            "severity_band": "low",
            "dynamic_requested": False,
            "dynamic_request_decision": "skip_low_risk",
            "dynamic_skip_reason": "skip_low_risk",
            "dynamic_policy_profile": "baseline_v1",
            "dynamic_reason_codes": ["low_risk_static_verdict"],
            "dynamic_status": "not_requested",
            "dynamic_added_ioc_count": 0,
            "dynamic_added_evidence_count": 0,
            "dynamic_ioc_types": [],
            "static_ioc_count": 1,
            "dynamic_ioc_count": 0,
        },
        {
            "sample_id": "b",
            "label": 1,
            "file_family": "office_macro",
            "severity_band": "high",
            "dynamic_requested": True,
            "dynamic_request_decision": "request_dynamic",
            "dynamic_skip_reason": "",
            "dynamic_policy_profile": "baseline_v1",
            "dynamic_reason_codes": ["macro_indicator"],
            "dynamic_status": "completed",
            "dynamic_added_ioc_count": 2,
            "dynamic_added_evidence_count": 1,
            "dynamic_ioc_types": ["domain", "ip"],
            "static_ioc_count": 2,
            "dynamic_ioc_count": 2,
        },
        {
            "sample_id": "c",
            "label": 1,
            "file_family": "archive_nested_archive",
            "severity_band": "high",
            "dynamic_requested": False,
            "dynamic_request_decision": "request_but_provider_unavailable",
            "dynamic_skip_reason": "provider_unavailable",
            "dynamic_policy_profile": "baseline_v1",
            "dynamic_reason_codes": ["signature_hit", "provider_unavailable"],
            "dynamic_status": "unavailable",
            "dynamic_added_ioc_count": 0,
            "dynamic_added_evidence_count": 0,
            "dynamic_ioc_types": [],
            "static_ioc_count": 3,
            "dynamic_ioc_count": 0,
        },
    ]
    report = build_file_dynamic_policy_report(predictions)
    overall = report["overall"]
    assert overall["sample_count"] == 3
    assert overall["request_rate"] == 0.3333
    assert overall["skip_rate"] == 0.3333
    assert report["dynamic_states"]["requested_but_provider_unavailable_count"] == 1
    assert report["request_decisions"]["request_dynamic"]["count"] == 1
    assert report["skip_reasons"]["skip_low_risk"]["count"] == 1
    assert report["reason_codes"]["macro_indicator"]["count"] == 1
    assert report["slices"]["file_family"]["office_macro"]["sample_count"] == 1
    assert report["slices"]["severity_band"]["high"]["sample_count"] == 2
    assert report["informational_deltas"]["additional_iocs_from_dynamic_total"] == 2


def test_file_dynamic_policy_gate_requires_sections_and_reason_codes():
    thresholds = {
        "file_dynamic_policy": {
            "required_sections": ["overall", "dynamic_states", "request_decisions"],
            "require_reason_code_for_actionable_decisions": True,
            "required_dynamic_state_keys": [
                "completed_rate",
                "unavailable_rate",
                "failed_rate",
                "running_or_deferred_rate",
                "not_requested_rate",
                "requested_but_provider_unavailable_count",
            ],
            "benign_family_request_rate_ceiling": {
                "enabled": True,
                "min_sample_count": 2,
                "max_request_rate": 0.2,
            },
        }
    }
    report = {
        "overall": {
            "sample_count": 2,
            "request_rate": 0.5,
            "missing_reason_code_count": 1,
        },
        "request_decisions": {},
        "dynamic_states": {
            "completed_rate": 0.0,
            "unavailable_rate": 0.0,
            "failed_rate": 0.0,
            "running_or_deferred_rate": 0.0,
            "not_requested_rate": 1.0,
            "requested_but_provider_unavailable_count": 0,
        },
        "slices": {
            "file_family": {
                "pdf": {
                    "sample_count": 2,
                    "benign_only": True,
                    "request_rate": 0.5,
                }
            }
        },
    }
    gate = evaluate_file_dynamic_policy_gate(results={"file": {"dynamic_policy": report}}, thresholds=thresholds)
    assert gate["passed"] is False
    assert any("missing reason codes" in reason for reason in gate["reasons"])
    assert any("request_rate" in reason for reason in gate["reasons"])


def test_file_dynamic_policy_artifacts_are_persisted(tmp_path):
    report = {
        "overall": {"sample_count": 1, "request_rate": 0.0},
        "request_decisions": {"not_requested": {"count": 1, "rate": 1.0}},
        "skip_reasons": {},
        "reason_codes": {},
        "policy_profiles": {"baseline_v1": {"count": 1, "rate": 1.0}},
        "provider_readiness": {"run_label": "disabled"},
        "dynamic_states": {
            "distribution": {"not_requested": {"count": 1, "rate": 1.0}},
            "completed_rate": 0.0,
            "unavailable_rate": 0.0,
            "failed_rate": 0.0,
            "running_or_deferred_rate": 0.0,
            "not_requested_rate": 1.0,
            "requested_but_provider_unavailable_count": 0,
        },
        "slices": {},
        "informational_deltas": {"additional_iocs_from_dynamic_total": 0},
        "limitations": [],
    }
    _persist_file_dynamic_policy_artifacts(tmp_path, report)
    expected = [
        "file_dynamic_policy_overall.json",
        "file_dynamic_policy_request_decisions.json",
        "file_dynamic_policy_reason_codes.json",
        "file_dynamic_policy_skip_reasons.json",
        "file_dynamic_policy_policy_profiles.json",
        "file_dynamic_policy_dynamic_states.json",
        "file_dynamic_policy_provider_readiness.json",
        "file_dynamic_policy_family_severity_slices.json",
        "file_dynamic_policy_ioc_evidence_deltas.json",
        "file_dynamic_policy_summary.json",
        "file_dynamic_policy_summary.md",
    ]
    for name in expected:
        assert (tmp_path / name).exists(), name


def test_resolve_file_dynamic_runtime_modes():
    class _Args:
        file_dynamic_mode = "fake"
        file_dynamic_poll_interval_seconds = 0.05
        file_dynamic_max_wait_seconds = 1.0
        file_dynamic_fake_completion_polls = 2
        file_dynamic_fake_fail = False
        file_dynamic_fake_failure_reason = "provider_failed"
        file_http_provider_base_url = ""
        file_http_provider_api_key = ""
        file_http_provider_submit_path = "/v1/dynamic/submit"
        file_http_provider_status_path_template = "/v1/dynamic/status/{submission_id}"
        file_http_provider_result_path_template = "/v1/dynamic/result/{submission_id}"
        file_http_provider_timeout_seconds = 10.0
        file_http_provider_insecure = False

    cfg = _resolve_file_dynamic_runtime(_Args())
    assert cfg["mode"] == "fake"
    assert cfg["enabled"] is True
    assert cfg["provider_name"] == "fake"
    assert cfg["provider_config"]["completion_polls"] == 2


def test_resolve_dynamic_provider_run_label_prefers_readiness_state():
    status = {"readiness_state": "live_validated", "active_provider": "http", "configured": True}
    label = _resolve_dynamic_provider_run_label(status, runtime_mode="http")
    assert label == "live_validated"


def test_resolve_dynamic_provider_run_label_handles_misconfigured_http():
    status = {"active_provider": "http", "configured": False}
    label = _resolve_dynamic_provider_run_label(status, runtime_mode="http")
    assert label == "misconfigured"
