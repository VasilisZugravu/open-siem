"""Unit tests for app.feeds.FeedManager. Popen is monkeypatched so no real
subprocesses are spawned."""
from app.feeds import FEEDS, FeedManager


class FakeProcess:
    def __init__(self):
        self._terminated = False

    def poll(self):
        return None if not self._terminated else 0

    def terminate(self):
        self._terminated = True


def _patch_popen(monkeypatch):
    created = []

    def fake_popen(*args, **kwargs):
        proc = FakeProcess()
        created.append(proc)
        return proc

    monkeypatch.setattr("app.feeds.subprocess.Popen", fake_popen)
    return created


def test_feeds_dict_has_three_entries():
    assert set(FEEDS.keys()) == {"machine", "incidents", "synthetic"}
    for feed in FEEDS.values():
        assert "label" in feed
        assert "args" in feed


def test_start_marks_feed_running(monkeypatch):
    _patch_popen(monkeypatch)
    manager = FeedManager()

    assert not manager.is_running("machine")
    started = manager.start("machine")
    assert started is True
    assert manager.is_running("machine")


def test_start_twice_is_noop(monkeypatch):
    _patch_popen(monkeypatch)
    manager = FeedManager()

    assert manager.start("machine") is True
    assert manager.start("machine") is False  # already running
    assert manager.is_running("machine")


def test_stop_marks_feed_stopped(monkeypatch):
    _patch_popen(monkeypatch)
    manager = FeedManager()

    manager.start("incidents")
    assert manager.stop("incidents") is True
    assert not manager.is_running("incidents")


def test_stop_when_not_running_is_noop(monkeypatch):
    _patch_popen(monkeypatch)
    manager = FeedManager()

    assert manager.stop("synthetic") is False


def test_status_reports_all_feeds(monkeypatch):
    _patch_popen(monkeypatch)
    manager = FeedManager()

    manager.start("machine")
    status = manager.status()
    assert status == {"machine": True, "incidents": False, "synthetic": False}


def test_start_unknown_feed_raises(monkeypatch):
    _patch_popen(monkeypatch)
    manager = FeedManager()

    try:
        manager.start("nope")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_stop_all_terminates_running_feeds(monkeypatch):
    _patch_popen(monkeypatch)
    manager = FeedManager()

    manager.start("machine")
    manager.start("incidents")
    manager.stop_all()

    assert not manager.is_running("machine")
    assert not manager.is_running("incidents")
