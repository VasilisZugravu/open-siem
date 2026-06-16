import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

# attack-lab/ has a hyphen so it can't be imported normally — use importlib
_spec = importlib.util.spec_from_file_location(
    "validate",
    Path(__file__).parent.parent / "attack-lab" / "validate.py",
)
_validate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_validate)

_write_coverage_md = _validate._write_coverage_md
_poll_alert = _validate._poll_alert
SCENARIOS = _validate.SCENARIOS


def test_write_coverage_md_all_passing(tmp_path):
    results = [(s, "✅") for s in SCENARIOS]
    out = str(tmp_path / "COVERAGE.md")
    _write_coverage_md(results, out)
    content = Path(out).read_text(encoding="utf-8")
    assert "✅" in content
    assert "RULE-001" in content
    assert "RULE-008" in content
    assert content.count("| 0") == 8  # 8 scenario rows


def test_write_coverage_md_pending(tmp_path):
    results = [(s, "⏳") for s in SCENARIOS]
    out = str(tmp_path / "COVERAGE.md")
    _write_coverage_md(results, out)
    content = Path(out).read_text(encoding="utf-8")
    assert "⏳" in content
    assert "✅" not in content
    assert "❌" not in content


def test_poll_alert_found():
    alert = {
        "id": 1, "rule_id": "RULE-001", "title": "SSH Brute Force",
        "severity": "medium", "created_at": "2026-06-16T10:00:00", "host": "linux-vm",
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps([alert]).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = _poll_alert("http://localhost:5000", "RULE-001", "2026-06-16T09:00:00", timeout=10)

    assert result == alert


def test_poll_alert_sends_api_key_header():
    """When api_key is provided, the request must carry X-Api-Key."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps([{"id": 1}]).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        _poll_alert(
            "http://localhost:5000", "RULE-001", "2026-06-16T09:00:00",
            api_key="my-key", timeout=10,
        )

    req = mock_urlopen.call_args[0][0]
    # urllib stores headers with capitalize() normalisation: "X-api-key"
    assert req.get_header("X-api-key") == "my-key"


def test_poll_alert_timeout():
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps([]).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with patch("time.sleep"):
            result = _poll_alert("http://localhost:5000", "RULE-001", "2026-06-16T09:00:00", timeout=0)

    assert result is None
