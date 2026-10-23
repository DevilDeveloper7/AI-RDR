def test_health_returns_ok(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "ok"
    assert body["service"] == "ai-rdr-m6"
    assert body["api_version"] == "v1"
    assert "timestamp" in body


def test_unknown_route_returns_json_404(client):
    res = client.get("/api/v1/does-not-exist")
    assert res.status_code == 404
    assert res.get_json()["error"]["code"] == "NOT_FOUND"


def test_wrong_method_returns_json_405(client):
    res = client.post("/api/v1/health")
    assert res.status_code == 405
    assert res.get_json()["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_unexpected_error_hides_stack_trace(app):
    @app.get("/api/v1/_boom")
    def boom():
        raise RuntimeError("secret internal detail")

    res = app.test_client().get("/api/v1/_boom")
    assert res.status_code == 500
    assert res.get_json() == {
        "error": {"code": "INTERNAL_ERROR", "message": "An internal error occurred."}
    }
    assert b"secret internal detail" not in res.data
