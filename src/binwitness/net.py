"""HTTP access with an on-disk cache, retries and an offline mode.

Every answer a scan relies on is cached with the time it was fetched, so a result can state how old its
vulnerability data is, a rerun the same day costs no network round-trips, and ``--offline`` can replay a
scan on a machine that has no internet access (copy the cache directory over).
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import random
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from binwitness import __version__

USER_AGENT = f"binwitness/{__version__}"
# Hash-to-coordinate answers and published POMs never change once published; advisories do.
STABLE_MAX_AGE = 30 * 24 * 3600
RETRY_STATUSES = {429, 500, 502, 503, 504}
# Maven Central's search endpoint throttles hard; everything else tolerates the default pool size.
HOST_CONCURRENCY = {"search.maven.org": 2}
# Answers normally arrive within two seconds, but now and then a connection stalls without ever replying.
# A long timeout parks a worker on each stall for its full length; a short one gets it back to a retry.
REQUEST_TIMEOUT = 30
# Maven Central's search front end holds about a third of requests for 30 or 60 s before it passes on an answer
# the index produced in milliseconds. Asking again after a few seconds is quicker than waiting that out.
HOST_TIMEOUT = {"search.maven.org": 8}
# A connection is made within a second or not at all: on some routes a share of handshakes is dropped outright.
# A new connection, from another port, usually gets through, so waiting longer for the lost one only idles.
CONNECT_TIMEOUT = 10
# A connection's timeout does not cover the name lookup before it. When the resolver falls back to TCP and the
# DNS server never answers (seen behind WSL's resolver), getaddrinfo blocks for good and the scan with it.
# Looked-up addresses are kept for a few minutes, so a scan asks for each host about once.
DNS_TTL = 300
_addresses: dict[tuple[str, int], tuple[float, list]] = {}


class NetError(Exception):
    """The service could not be reached or kept failing after retries."""


class OfflineMiss(NetError):
    """Offline mode and the answer is not in the cache."""


Transport = Callable[[str, str, bytes | None, dict], tuple[int, bytes, dict]]


def map_parallel(function: Callable, items: Iterable, workers: int) -> list:
    """``ThreadPoolExecutor.map`` into a list, except that an interrupt does not wait for the queue: the pool's
    own exit would run every pending lookup, each up to a timeout and its retries, before Ctrl-C took effect."""
    pool = ThreadPoolExecutor(workers)
    try:
        return list(pool.map(function, items))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def resolve(host: str, port: int, timeout: float = REQUEST_TIMEOUT, lookup=socket.getaddrinfo) -> list:
    """getaddrinfo with a deadline. A lookup that never returns is left to its own thread."""
    cached = _addresses.get((host, port))
    if cached and time.monotonic() - cached[0] < DNS_TTL:
        return cached[1]
    answer = {}

    def run():
        try:
            answer["addresses"] = lookup(host, port, 0, socket.SOCK_STREAM)
        except OSError as error:
            answer["error"] = error

    worker = threading.Thread(target=run, name=f"resolve {host}", daemon=True)
    worker.start()
    worker.join(timeout)
    if "addresses" in answer:
        _addresses[(host, port)] = (time.monotonic(), answer["addresses"])
        return answer["addresses"]
    raise answer.get("error") or TimeoutError(f"name lookup of {host} got no answer in {timeout:g} s")


def _connect(address, timeout=REQUEST_TIMEOUT, source_address=None, *args, **kwargs):
    host, port = address
    failure = None
    for *_, target in resolve(host, port):
        try:
            connection = socket.create_connection(target[:2], min(timeout, CONNECT_TIMEOUT), source_address)
        except OSError as error:
            failure = error
            continue
        connection.settimeout(timeout)
        return connection
    raise failure or OSError(f"no address for {host}")


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTPConnection, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPSConnection, req, context=self._context)


_OPENER = urllib.request.build_opener(_HTTPHandler, _HTTPSHandler)


def open_url(request: urllib.request.Request, timeout: float = REQUEST_TIMEOUT):
    """``urllib.request.urlopen``, with the name lookup bounded by the timeout as well."""
    return _OPENER.open(request, timeout=timeout)


def urllib_transport(method: str, url: str, body: bytes | None, headers: dict) -> tuple[int, bytes, dict]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with open_url(request, HOST_TIMEOUT.get(request.host, REQUEST_TIMEOUT)) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read() or b"", dict(error.headers or {})


def default_cache_dir() -> Path:
    if os.environ.get("BINWITNESS_CACHE"):
        return Path(os.environ["BINWITNESS_CACHE"])
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "binwitness"


@dataclass
class Net:
    cache_dir: Path = field(default_factory=default_cache_dir)
    offline: bool = False
    max_age_hours: float = 12.0
    transport: Transport = urllib_transport
    retries: int = 6
    sleep: Callable[[float], None] = time.sleep
    # origin prefix -> mirror prefix, e.g. Maven Central -> a mirror closer to this machine
    mirrors: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        self.cache_dir = Path(self.cache_dir)
        self._lock = threading.Lock()
        self._host_slots: dict[str, threading.Semaphore] = {}
        self.fetched: dict[str, list[float]] = {}  # host -> [oldest, newest] fetch time of answers used
        self.offline_misses = 0
        self.offline_missed_hosts: Counter[str] = Counter()

    # ---- public helpers -------------------------------------------------------------------------------

    def get(self, url: str, *, stable: bool = False, headers: dict | None = None,
            refresh: bool = False) -> bytes | None:
        """Body of a GET, or None when the server says 404."""
        status, body = self.request("GET", url, stable=stable, headers=headers, refresh=refresh)
        return None if status == 404 else body

    def get_json(self, url: str, *, stable: bool = False, headers: dict | None = None, refresh: bool = False):
        body = self.get(url, stable=stable, headers=headers, refresh=refresh)
        return None if body is None else json.loads(body)

    def post_json(self, url: str, payload, *, stable: bool = False):
        status, body = self.request("POST", url, payload, stable=stable)
        return None if status == 404 else json.loads(body)

    def provenance(self) -> dict:
        def iso(epoch):
            return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")
        return {host: {"oldest": iso(span[0]), "newest": iso(span[1])} for host, span in sorted(self.fetched.items())}

    def route(self, url: str) -> str:
        """The URL actually fetched: a configured mirror stands in for its origin."""
        for origin, mirror in self.mirrors.items():
            if url.startswith(origin + "/"):
                return mirror + url[len(origin):]
        return url

    # ---- core -----------------------------------------------------------------------------------------

    def request(self, method: str, url: str, payload=None, *, stable: bool = False,
                headers: dict | None = None, refresh: bool = False) -> tuple[int, bytes]:
        # Routed before the cache key is made, so a mirror's answers are cached and reported as the mirror's.
        url = self.route(url)
        body = None if payload is None else json.dumps(payload, sort_keys=True).encode()
        # A byte range is a different answer from the same URL; other headers do not change the answer.
        span = (headers or {}).get("Range")
        material = f"{method} {url}\n" + (f"Range: {span}\n" if span else "")
        key = hashlib.sha256(material.encode() + (body or b"")).hexdigest()
        path = self.cache_dir / key[:2] / f"{key}.json"
        cached = self._load(path)
        max_age = STABLE_MAX_AGE if stable else self.max_age_hours * 3600
        if cached and (self.offline or (not refresh and time.time() - cached["fetched"] <= max_age)):
            self._note(url, cached["fetched"])
            return cached["status"], base64.b64decode(cached["body"])
        if self.offline:
            with self._lock:
                self.offline_misses += 1
                self.offline_missed_hosts[urllib.parse.urlsplit(url).netloc] += 1
            raise OfflineMiss(url)
        sent = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}
        if body is not None:
            sent["Content-Type"] = "application/json"
        sent.update(headers or {})
        status, content = self._send(method, url, body, sent)
        now = time.time()
        if status in (200, 206, 404):
            self._store(path, {"url": url, "status": status, "fetched": now,
                               "body": base64.b64encode(content).decode()})
            self._note(url, now)
            return status, content
        raise NetError(f"{method} {url}: HTTP {status}")

    def _send(self, method, url, body, headers):
        host = urllib.parse.urlsplit(url).hostname or ""
        with self._lock:
            slot = self._host_slots.setdefault(host, threading.Semaphore(HOST_CONCURRENCY.get(host, 16)))
        last = None
        for attempt in range(self.retries):
            try:
                with slot:
                    status, content, response_headers = self.transport(method, url, body, headers)
                if status not in RETRY_STATUSES:
                    return status, content
                last = f"HTTP {status}"
                wait = _retry_after(response_headers)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
                last, wait = repr(error), None
            if attempt + 1 < self.retries:
                # Exponential backoff spanning about a minute: long enough to ride out a brief network drop
                # instead of losing a scan that has already been running for many minutes.
                self.sleep(wait if wait is not None else 2 ** (attempt + 1) + random.random())
        raise NetError(f"{method} {url}: {last} after {self.retries} attempts")

    def _load(self, path: Path):
        try:
            return json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            return None

    def _store(self, path: Path, record: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        temporary.write_text(json.dumps(record), "utf-8")
        os.replace(temporary, path)

    def _note(self, url: str, epoch: float):
        host = urllib.parse.urlsplit(url).hostname or url
        with self._lock:
            span = self.fetched.setdefault(host, [epoch, epoch])
            span[0], span[1] = min(span[0], epoch), max(span[1], epoch)


def _retry_after(headers: dict) -> float | None:
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    try:
        return min(float(value), 60.0) if value is not None else None
    except ValueError:
        return None
