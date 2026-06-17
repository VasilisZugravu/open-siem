def test_security_headers_present_on_every_response(client):
    """The dashboard renders attacker-influenced event data (host, command
    lines, etc. from /ingest); these headers are baseline defense-in-depth
    against XSS/clickjacking even when escaping is correct everywhere else."""
    response = client.get("/")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"]
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_security_headers_present_on_json_api_response(client):
    response = client.get("/api/feed")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
