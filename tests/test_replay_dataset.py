class _FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {"id": 1}


def test_post_event_sends_api_key_header_when_configured(monkeypatch):
    import scripts.replay_dataset as replay_dataset

    monkeypatch.setattr(replay_dataset, "API_KEY", "test-key")
    captured = {}

    def fake_post(url, json=None, headers=None, **kwargs):
        captured["headers"] = headers
        return _FakeResponse()

    monkeypatch.setattr(replay_dataset.requests, "post", fake_post)

    replay_dataset.post_event("http://localhost:5000", {"event_type": "x", "host": "h"})

    assert captured["headers"] == {"X-Api-Key": "test-key"}


def test_post_event_sends_no_header_when_api_key_unset(monkeypatch):
    import scripts.replay_dataset as replay_dataset

    monkeypatch.setattr(replay_dataset, "API_KEY", "")
    captured = {}

    def fake_post(url, json=None, headers=None, **kwargs):
        captured["headers"] = headers
        return _FakeResponse()

    monkeypatch.setattr(replay_dataset.requests, "post", fake_post)

    replay_dataset.post_event("http://localhost:5000", {"event_type": "x", "host": "h"})

    assert captured["headers"] == {}
