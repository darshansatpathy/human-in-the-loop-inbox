from __future__ import annotations

import pytest
from conftest import ROOT

from hitl.cli import main


def test_cli(database_url, monkeypatch, capsys):
    monkeypatch.setenv("HITL_DATABASE_URL", database_url)
    monkeypatch.setenv("HITL_POLICY_FILE", str(ROOT / "policy.yaml"))
    assert main(["migrate"]) == 0
    assert main(["add-agent", "cli-bot"]) == 0
    assert capsys.readouterr().out.strip().splitlines()[-1].startswith("ak_")
    assert main(["add-reviewer", "zed@example.com", "--name", "Zed", "--groups", "finance, oncall"]) == 0
    assert capsys.readouterr().out.strip().startswith("rt_")
    assert main(["check-policy", "--file", str(ROOT / "policy.yaml"), "--action", "issue_refund", "--args", '{"amount": 5000}']) == 0
    assert '"rule": "large-refunds"' in capsys.readouterr().out
    assert main(["verify-audit"]) == 0
    assert "chain intact" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--version"])
