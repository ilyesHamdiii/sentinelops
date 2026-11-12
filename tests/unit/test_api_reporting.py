from fastapi.testclient import TestClient

from sentinelops.api.app import app

client = TestClient(app)


def test_health_and_read_only_metrics_are_available():
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    summary = client.get("/metrics/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["total_findings"] == 3
    assert payload["open_findings"] == 2
    assert payload["max_risk_score"] == 96


def test_findings_assets_and_scenarios_are_traceable_and_paginated():
    findings = client.get("/findings?status=OPEN&page=1&limit=2")
    assert findings.status_code == 200
    payload = findings.json()
    assert payload["count"] == 2
    assert payload["page"] == 1
    assert payload["items"][0]["id"] == "fg-001"

    asset_list = client.get("/assets")
    assert asset_list.status_code == 200
    assert asset_list.json()["count"] == 3

    scenarios = client.get("/scenarios")
    assert scenarios.status_code == 200
    assert len(scenarios.json()["items"]) == 3


def test_finding_and_report_endpoints_are_sanitized():
    finding = client.get("/findings/fg-002")
    assert finding.status_code == 200
    payload = finding.json()
    assert payload["id"] == "fg-002"
    assert payload["resource_id"] == "arn:aws:s3:::example-bucket"

    report = client.get("/reports/rpt-001")
    assert report.status_code == 200
    body = report.json()
    assert body["report_id"] == "rpt-001"
    assert body["summary"]["total_findings"] == 3
    assert "secret" not in str(body).lower()
    assert "aws_access_key_id" not in str(body).lower()
    assert "password" not in str(body).lower()


def test_write_operations_require_approver_role():
    rejected = client.post("/remediations/rm-001/approve", json={"actor": "alice"})
    assert rejected.status_code == 403
    assert "approver" in rejected.json()["detail"].lower()

    approved = client.post(
        "/remediations/rm-001/approve",
        json={"actor": "alice", "decision": "approve", "reason": "Restrict public access."},
        headers={"x-sentinelops-role": "approver"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"

    details = client.get("/remediations/rm-001", headers={"x-sentinelops-role": "reader"})
    assert details.status_code == 200
    assert details.json()["id"] == "rm-001"
    assert details.json()["approved"] is True


def test_execute_endpoint_requires_approver_role_and_verification():
    execution = client.post(
        "/remediations/rm-001/execute",
        json={"status": "SUCCESS", "verification_passed": True},
        headers={"x-sentinelops-role": "approver"},
    )
    assert execution.status_code == 200
    assert execution.json()["status"] == "VERIFIED"

    rejected = client.post(
        "/remediations/rm-001/execute",
        json={"status": "FAILED", "verification_passed": False},
        headers={"x-sentinelops-role": "reader"},
    )
    assert rejected.status_code == 403
    assert "approver" in rejected.json()["detail"].lower()


def test_root_and_dashboard_routes_are_rejected_for_headless_backend():
    root = client.get("/")
    assert root.status_code == 404
    assert "headless" in root.json()["detail"].lower()

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 404
    assert "headless" in dashboard.json()["detail"].lower()


def test_read_only_routes_work_without_auth_headers():
    assert client.get("/health").status_code == 200
    assert client.get("/metrics/summary").status_code == 200
    assert client.get("/findings").status_code == 200
    assert client.get("/reports/rpt-001").status_code == 200
