"""The real transport: name lookups bounded by the request timeout."""
import http.server
import socket
import threading
import time

import pytest

from binwitness import net


@pytest.fixture(autouse=True)
def fresh_addresses():
    net._addresses.clear()
    yield
    net._addresses.clear()


def test_a_name_lookup_that_never_answers_gives_up_at_the_deadline():
    released = threading.Event()

    def stuck(host, port, *args):
        released.wait(5)
        return []

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="name lookup of mirror.example got no answer"):
        net.resolve("mirror.example", 443, timeout=0.2, lookup=stuck)
    assert time.monotonic() - started < 2
    released.set()


def test_addresses_are_looked_up_once_then_reused():
    calls = []

    def lookup(host, port, *args):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    assert net.resolve("a.example", 443, lookup=lookup) == net.resolve("a.example", 443, lookup=lookup)
    assert calls == ["a.example"]


def test_a_failed_lookup_is_not_remembered():
    def missing(host, port, *args):
        raise socket.gaierror("no such host")

    with pytest.raises(socket.gaierror):
        net.resolve("gone.example", 443, lookup=missing)
    assert ("gone.example", 443) not in net._addresses


def test_a_connection_gets_less_time_than_a_reply(monkeypatch):
    """A lost handshake is retried after CONNECT_TIMEOUT; the answer still gets the full request timeout."""
    asked = []

    class Connection:
        def settimeout(self, value):
            asked.append(("reply", value))

    def create_connection(target, timeout, source_address=None):
        asked.append(("connect", timeout))
        return Connection()

    monkeypatch.setattr(net.socket, "create_connection", create_connection)
    net._addresses[("a.example", 443)] = (time.monotonic(), [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                                              ("192.0.2.1", 443))])
    net._connect(("a.example", 443), 30)
    assert asked == [("connect", net.CONNECT_TIMEOUT), ("reply", 30)]


class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *args):
        pass


def test_requests_go_through_the_bounded_lookup():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        status, body, _ = net.urllib_transport("GET", f"http://localhost:{port}/", None, {})
        assert (status, body) == (200, b"hello")
        assert ("localhost", port) in net._addresses
    finally:
        server.shutdown()


def answering(method, url, body, headers):
    return 200, b"answer", {}


def test_an_answer_whose_cache_file_cannot_be_replaced_is_still_returned_and_stored_once_it_can(tmp_path, monkeypatch):
    refusals, replace = [2], net.os.replace

    def refusing(source, target):
        if refusals[0]:
            refusals[0] -= 1
            raise PermissionError(13, "Access is denied")
        replace(source, target)
    monkeypatch.setattr(net.os, "replace", refusing)
    fetcher = net.Net(cache_dir=tmp_path, transport=answering, sleep=lambda s: None)
    assert fetcher.get("https://repo.example/a.sha1", stable=True) == b"answer"
    assert [path.suffix for path in tmp_path.rglob("*.*")] == [".json"]


def test_an_answer_whose_cache_file_is_never_replaced_is_returned_and_leaves_no_temporary(tmp_path, monkeypatch):
    def refusing(source, target):
        raise PermissionError(13, "Access is denied")
    monkeypatch.setattr(net.os, "replace", refusing)
    fetcher = net.Net(cache_dir=tmp_path, transport=answering, sleep=lambda s: None)
    assert fetcher.get("https://repo.example/a.sha1", stable=True) == b"answer"
    assert not [path for path in tmp_path.rglob("*") if path.is_file()]
