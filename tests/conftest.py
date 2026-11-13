from __future__ import annotations

import pytest

import sentinelops.remediation as remediation_module


@pytest.fixture(autouse=True)
def isolated_remediation_ledgers(monkeypatch, tmp_path):
    """Prevent approval/session replay data from leaking across tests while preserving the durable production ledger by default."""
    approval_db = tmp_path / "approval-ledger.sqlite3"
    session_db = tmp_path / "session-ledger.sqlite3"

    monkeypatch.setattr(
        remediation_module,
        "_APPROVAL_LEDGER",
        remediation_module._ApprovalLedger(approval_db),
    )
    monkeypatch.setattr(
        remediation_module,
        "_SESSION_LEDGER",
        remediation_module._SessionLedger(session_db),
    )

    yield
