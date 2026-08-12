import http.client
import json

import pytest


PROM_PORT = 9099


def _config(fmt, sessions=False):
    return f"""
    [modules]
    metrics

    [core]
    log-error=/dev/stderr

    [log]
    log-emerg=/dev/stderr
    level=1

    [cli]
    tcp=127.0.0.1:2001

    [metrics]
    address=127.0.0.1:{PROM_PORT}
    format={fmt}
    sessions={int(sessions)}
    """


def _request(path, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", PROM_PORT, timeout=5)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        # strict: the renderer must never emit a body that is not valid UTF-8
        body = resp.read().decode("utf-8")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, body
    finally:
        conn.close()


class TestPrometheus:
    @pytest.fixture()
    def accel_pppd_config(self):
        # sessions=1 must stay a no-op here: prometheus output is aggregate only
        return _config("prometheus", sessions=True)

    def test_metrics_prometheus(self, accel_pppd_instance):
        assert accel_pppd_instance

        status, headers, body = _request("/metrics")

        assert status == 200
        assert "text/plain" in headers.get("content-type", "")
        assert "accel_ppp_build_info{version=" in body
        assert "# TYPE accel_ppp_uptime_seconds gauge" in body
        assert 'accel_ppp_sessions{state="active"}' in body
        assert "session_details" not in body

    def test_metrics_404_unknown_path(self, accel_pppd_instance):
        assert accel_pppd_instance

        status, _, _ = _request("/nope")

        assert status == 404

    def test_metrics_405_non_get(self, accel_pppd_instance):
        assert accel_pppd_instance

        status, _, _ = _request("/metrics", method="POST")

        assert status == 405


class TestJson:
    @pytest.fixture()
    def accel_pppd_config(self):
        return _config("json", sessions=True)

    def test_metrics_json(self, accel_pppd_instance):
        assert accel_pppd_instance

        status, headers, body = _request("/metrics")

        assert status == 200
        assert headers.get("content-type") == "application/json"

        assert int(headers["content-length"]) == len(body.encode("utf-8"))

        doc = json.loads(body)
        assert "build" in doc and "version" in doc["build"]
        assert "uptime_seconds" in doc
        assert "active" in doc["sessions"]
        assert "threads" in doc["core"]
        assert doc["session_details"] == []


class TestJsonNoSessions:
    @pytest.fixture()
    def accel_pppd_config(self):
        return _config("json")

    def test_metrics_json_without_sessions(self, accel_pppd_instance):
        assert accel_pppd_instance

        status, _, body = _request("/metrics")

        assert status == 200
        assert "session_details" not in json.loads(body)
