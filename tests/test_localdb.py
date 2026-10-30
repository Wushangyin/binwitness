"""Local datasets: syncing (full, incremental, resumed), OSV range evaluation, and scans that use them."""
import base64
import gzip
import hashlib
import io
import json
import sqlite3
import struct
import tarfile
import threading
import time
import urllib.parse
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from binwitness import localdb, maven
from binwitness.cli import main
from binwitness.localdb import Fetcher, LocalDb, SyncError, expand
from binwitness.net import Net
from binwitness.output import render_summary
from binwitness.scan import OFFLINE_UNKNOWN, Options, scan
from binwitness.vulns import affects

from helpers import ScriptedTransport, Served, make_jar, make_zip
from test_scan import NETTY_ALL, PUBLISHED, RECORDS, routes


def opener(transport):
    def open_(url, headers):
        status, body, answer = transport("GET", url, None, headers)
        return status, answer, io.BytesIO(body)
    return open_


def fetcher(transport):
    return Fetcher(opener=opener(transport), sleep=lambda s: None)


def advisory(osv_id, name, events=None, modified="2026-01-01T00:00:00Z", ecosystem="Maven", **extra):
    return {"id": osv_id, "modified": modified, "aliases": [], **extra,
            "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": events or [{"introduced": "0"},
                                                                                {"fixed": "2.0"}]}]}]}


def osv_zip(*records):
    return Served(make_zip({f"{r['id']}.json": json.dumps(r) for r in records}))


def changes(*rows):
    return Served("".join(f"{stamp},{record_id}\n" for stamp, record_id in rows).encode())


def never(method, url, body):
    raise AssertionError(f"unexpected request {url}")


# ---- OSV evaluation ------------------------------------------------------------------------------------

def ranged(*events, kind="ECOSYSTEM", ecosystem="Maven", name="g:a", versions=None):
    entry = {"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": kind, "events": list(events)}]}
    return {"id": "X", "affected": [entry | ({"versions": versions} if versions else {})]}


@pytest.mark.parametrize("record, version, expected", [
    (ranged({"introduced": "0"}, {"fixed": "2.0"}), "1.9", True),
    (ranged({"introduced": "0"}, {"fixed": "2.0"}), "2.0", False),
    (ranged({"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"fixed": "2.5"}), "1.7", False),
    (ranged({"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"fixed": "2.5"}), "2.1", True),
    (ranged({"introduced": "1.0"}, {"fixed": "1.5"}), "0.9", False),
    (ranged({"fixed": "2.0"}, {"introduced": "1.0"}), "1.5", True),
    (ranged({"introduced": "2.0"}, {"fixed": "2.5"}, {"introduced": "1.0"}, {"fixed": "1.5"}), "2.1", True),
    (ranged({"introduced": "0"}, {"last_affected": "1.4"}), "1.4", True),
    (ranged({"introduced": "0"}, {"last_affected": "1.4"}), "1.4.1", False),
    (ranged({"introduced": "0"}, {"limit": "3.0"}), "2.0", True),
    (ranged({"introduced": "0"}, {"limit": "3.0"}), "3.1", False),
    (ranged({"introduced": "0"}, {"fixed": "2.9.10.1"}), "2.9.10", True),
    (ranged({"introduced": "0"}, kind="GIT"), "1.0", False),
    (ranged({"introduced": "0"}, name="g:other"), "1.0", False),
    (ranged({"introduced": "5.0"}, versions=["1.0", "1.1"]), "1.1", True),
])
def test_affects_follows_osv_evaluation(record, version, expected):
    assert affects(record, "maven", "g:a", version) is expected


def test_affects_semver_prereleases():
    record = ranged({"introduced": "0"}, {"fixed": "1.2.3"}, kind="SEMVER", ecosystem="npm", name="left-pad")
    assert affects(record, "npm", "left-pad", "1.2.3-beta.1")
    assert not affects(record, "npm", "left-pad", "1.2.3")


# ---- syncing -------------------------------------------------------------------------------------------

def test_full_sync_then_incremental_update(tmp_path, monkeypatch):
    monkeypatch.setattr(localdb, "CSV_CHUNK", 40)  # several ranged reads, lines split across them
    old = advisory("GHSA-old", "org.example:lib", modified="2026-01-01T00:00:00.123Z")
    gone = advisory("GHSA-gone", "org.example:lib")
    retracted = advisory("GHSA-retracted", "org.example:lib", withdrawn="2026-01-02T00:00:00Z")
    transport = ScriptedTransport({"/Maven/all.zip": osv_zip(old, gone, retracted)})
    db = LocalDb(tmp_path / "db")
    assert db.sync(["osv-maven"], fetcher=fetcher(transport), log=lambda m: None) == {
        "osv-maven": "downloaded 3 records"}
    assert [r["id"] for r in db.osv_records("maven", "org.example:lib")] == ["GHSA-gone", "GHSA-old"]
    assert db.state["osv-maven"]["data_as_of"] == "2026-01-01T00:00:00.123000000"

    fixed_earlier = advisory("GHSA-old", "org.example:lib", [{"introduced": "0"}, {"fixed": "1.0"}],
                             modified="2026-02-01T00:00:00.5Z")
    added = advisory("GHSA-new", "org.example:lib", modified="2026-01-15T00:00:00Z")
    transport = ScriptedTransport({
        "/Maven/modified_id.csv": changes(("2026-02-01T00:00:00.5Z", "GHSA-old"),
                                          ("2026-01-15T00:00:00Z", "GHSA-new"),
                                          ("2026-01-10T00:00:00Z", "GHSA-gone"),
                                          ("2025-12-01T00:00:00Z", "GHSA-ancient")),
        "/Maven/GHSA-old.json": fixed_earlier, "/Maven/GHSA-new.json": added, "/Maven/GHSA-gone.json": None,
        "/Maven/GHSA-ancient.json": never, "/Maven/all.zip": never})
    db = LocalDb(tmp_path / "db")
    assert db.sync(["osv-maven"], fetcher=fetcher(transport), log=lambda m: None) == {
        "osv-maven": "updated: 2 records changed, 1 removed"}
    assert sorted(r["id"] for r in db.osv_records("maven", "org.example:lib")) == ["GHSA-new", "GHSA-old"]
    assert not affects(db.osv_records("maven", "org.example:lib")[1], "maven", "org.example:lib", "1.5")
    assert db.state["osv-maven"]["data_as_of"] == "2026-02-01T00:00:00.500000000"
    assert db.state["osv-maven"]["records"] == 3  # old, new, retracted (kept, filtered when matching)


def test_records_fetched_again_at_the_copy_time_are_not_reported_as_changes(tmp_path):
    held = advisory("GHSA-held", "g:a", modified="2026-03-01T00:00:00Z")
    db = LocalDb(tmp_path)
    db.sync(["osv-maven"], fetcher=fetcher(ScriptedTransport({"/Maven/all.zip": osv_zip(held)})), log=lambda m: None)
    # The newest entry is the copy's own newest record, fetched again by design.
    same = ScriptedTransport({"/Maven/modified_id.csv": changes(("2026-03-01T00:00:00Z", "GHSA-held"),
                                                                ("2026-02-01T00:00:00Z", "GHSA-older")),
                              "/Maven/GHSA-held.json": held, "/Maven/GHSA-older.json": never})
    assert db.sync(["osv-maven"], fetcher=fetcher(same), log=lambda m: None) == {"osv-maven": "up to date"}
    edited = advisory("GHSA-held", "g:a", [{"introduced": "0"}, {"fixed": "3.0"}], modified="2026-03-02T00:00:00Z")
    one = ScriptedTransport({"/Maven/modified_id.csv": changes(("2026-03-02T00:00:00Z", "GHSA-held"),
                                                               ("2026-03-01T00:00:00Z", "GHSA-held")),
                             "/Maven/GHSA-held.json": edited})
    assert db.sync(["osv-maven"], fetcher=fetcher(one), log=lambda m: None) == {
        "osv-maven": "updated: 1 record changed"}
    assert affects(LocalDb(tmp_path).osv_records("maven", "g:a")[0], "maven", "g:a", "2.5")


def test_many_changes_download_the_archive_again(tmp_path, monkeypatch):
    first = advisory("GHSA-a", "g:a")
    db = LocalDb(tmp_path)
    db.sync(["osv-maven"], fetcher=fetcher(ScriptedTransport({"/Maven/all.zip": osv_zip(first)})), log=lambda m: None)
    monkeypatch.setattr(localdb, "INCREMENTAL_LIMIT", 1)
    transport = ScriptedTransport({"/Maven/modified_id.csv": changes(("2026-03-01T00:00:00Z", "GHSA-b"),
                                                                     ("2026-02-01T00:00:00Z", "GHSA-c")),
                                   "/Maven/all.zip": osv_zip(first, advisory("GHSA-b", "g:a"),
                                                             advisory("GHSA-c", "g:a")),
                                   "/Maven/GHSA-": never})
    assert db.sync(["osv-maven"], fetcher=fetcher(transport), log=lambda m: None) == {
        "osv-maven": "downloaded 3 records"}


def test_monthly_rebuild_drops_records_deleted_upstream(tmp_path):
    db = LocalDb(tmp_path)
    db.sync(["osv-maven"], fetcher=fetcher(ScriptedTransport({"/Maven/all.zip": osv_zip(advisory("GHSA-a", "g:a"))})),
            log=lambda m: None)
    month_ago = (datetime.now(timezone.utc) - timedelta(days=localdb.REBUILD_DAYS + 1)).isoformat()
    db.state["osv-maven"]["full_download"] = month_ago
    db._write_state()
    transport = ScriptedTransport({"/Maven/all.zip": osv_zip(advisory("GHSA-b", "g:a")), "modified_id": never})
    db.sync(["osv-maven"], fetcher=fetcher(transport), log=lambda m: None)
    assert [r["id"] for r in db.osv_records("maven", "g:a")] == ["GHSA-b"]


def test_failed_sync_keeps_the_installed_copy(tmp_path):
    db = LocalDb(tmp_path)
    db.sync(["osv-maven"], fetcher=fetcher(ScriptedTransport({"/Maven/all.zip": osv_zip(advisory("GHSA-a", "g:a"))})),
            log=lambda m: None)
    before = dict(db.state["osv-maven"])
    broken = ScriptedTransport({"/Maven/modified_id.csv": changes(("2026-03-01T00:00:00Z", "GHSA-b")),
                                "/Maven/GHSA-b.json": (503, b"")})
    outcome = db.sync(["osv-maven"], fetcher=fetcher(broken), log=lambda m: None)
    assert outcome["osv-maven"].startswith("failed")
    assert db.state["osv-maven"] == before
    assert [r["id"] for r in LocalDb(tmp_path).osv_records("maven", "g:a")] == ["GHSA-a"]


class Dropping(io.BytesIO):
    def read(self, size=-1):
        chunk = super().read(size)
        if not chunk:
            raise ConnectionResetError("connection reset by peer")
        return chunk


def test_download_resumes_after_a_dropped_connection(tmp_path):
    data = bytes(range(256)) * 40
    sent = []

    def open_(url, headers):
        sent.append(dict(headers))
        if len(sent) == 1:
            return 200, {"Content-Length": str(len(data)), "ETag": '"v1"'}, Dropping(data[:1000])
        start = int(headers["Range"][len("bytes="):-1])
        return 206, {"Content-Range": f"bytes {start}-{len(data) - 1}/{len(data)}"}, io.BytesIO(data[start:])

    target = tmp_path / "file"
    seen = []
    Fetcher(opener=open_, sleep=lambda s: None).download("https://x/f", target, sha256=f"sha256:{hashlib.sha256(data).hexdigest()}",
                                                        progress=lambda done, total: seen.append((done, total)))
    assert target.read_bytes() == data
    assert sent[1] == {"Range": "bytes=1000-", "If-Range": '"v1"'}
    assert seen[-1] == (len(data), len(data))


def test_kev_sync(tmp_path):
    catalog = {"dateReleased": "2026-10-28T17:00:00.000Z",
               "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
    db = LocalDb(tmp_path)
    assert db.sync(["kev"], fetcher=fetcher(ScriptedTransport({"known_exploited": catalog})), log=lambda m: None) == {
        "kev": "downloaded 1 entry"}
    assert db.kev() == {"CVE-2021-44228": "2021-12-10"}
    written = db.path("kev").stat().st_mtime_ns
    assert db.sync(["kev"], fetcher=fetcher(ScriptedTransport({"known_exploited": catalog})), log=lambda m: None) == {
        "kev": "up to date"}
    assert db.path("kev").stat().st_mtime_ns == written
    newer = {"dateReleased": "2026-10-29T17:00:00.000Z",
             "vulnerabilities": [*catalog["vulnerabilities"], {"cveID": "CVE-2026-0001", "dateAdded": "2026-10-29"}]}
    assert db.sync(["kev"], fetcher=fetcher(ScriptedTransport({"known_exploited": newer})), log=lambda m: None) == {
        "kev": "downloaded 2 entries"}
    assert LocalDb(tmp_path).kev()["CVE-2026-0001"] == "2026-10-29"


def test_concurrent_syncs_keep_each_others_datasets(tmp_path):
    catalog = {"dateReleased": "2026-10-28T17:00:00.000Z", "vulnerabilities": []}
    opened_earlier = LocalDb(tmp_path)
    LocalDb(tmp_path).sync(["kev"], fetcher=fetcher(ScriptedTransport({"known_exploited": catalog})),
                           log=lambda m: None)
    transport = ScriptedTransport({"Maven/all.zip": Served(osv_zip(advisory("GHSA-a", "g:a")))})
    opened_earlier.sync(["osv-maven"], fetcher=fetcher(transport), log=lambda m: None)
    assert LocalDb(tmp_path).installed() == ["osv-maven", "kev"]


def test_a_second_sync_on_the_same_directory_is_refused(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(localdb, "Fetcher", lambda: Fetcher(opener=lambda url, headers: never("GET", url, None)))
    with LocalDb(tmp_path)._exclusive():
        assert main(["db", "sync", "kev", "--db-dir", str(tmp_path)]) == 1
        assert main(["db", "remove", "kev", "--db-dir", str(tmp_path)]) == 1
    assert "another `binwitness db` command" in capsys.readouterr().err


def test_download_resumes_a_connection_closed_early(tmp_path):
    data = bytes(range(256)) * 40
    slept = []

    def open_(url, headers):
        # Every connection ends cleanly after 1000 bytes, as a dropped one looks to http.client.
        start = int(headers["Range"][len("bytes="):-1]) if "Range" in headers else 0
        piece = io.BytesIO(data[start:start + 1000])
        if start:
            return 206, {"Content-Range": f"bytes {start}-{len(data) - 1}/{len(data)}"}, piece
        return 200, {"Content-Length": str(len(data))}, piece

    target = tmp_path / "file"
    Fetcher(opener=open_, retries=3, sleep=slept.append).download(
        "https://x/f", target, sha256=f"sha256:{hashlib.sha256(data).hexdigest()}")
    assert target.read_bytes() == data
    assert slept == []


class RangeServer:
    """A file served as a CDN serves it: ranges with Content-Range, an ETag, and ``If-Range`` honoured."""

    def __init__(self, data: bytes, ranges: bool = True):
        self.data, self.etag, self.ranges = data, '"v1"', ranges
        self.asked, self.served = [], []  # served: the ranges sent whole
        self.cut = {}  # where a range starts: bytes sent before the connection drops
        self.refused = set()  # ranges answered 503

    def __call__(self, url, headers):
        span = headers.get("Range")
        self.asked.append(span)
        if not (self.ranges and span) or headers.get("If-Range", self.etag) != self.etag:
            return 200, {"Content-Length": str(len(self.data)), "ETag": self.etag}, io.BytesIO(self.data)
        start, _, end = span[len("bytes="):].partition("-")
        if span in self.refused:
            return 503, {}, io.BytesIO(b"")
        start, end = int(start), int(end) if end else len(self.data) - 1
        body = self.data[start:end + 1][:self.cut.pop(start, None)]
        if len(body) == end + 1 - start:
            self.served.append(span)
        return 206, {"Content-Range": f"bytes {start}-{end}/{len(self.data)}", "ETag": self.etag}, io.BytesIO(body)


PARTS = ["bytes=0-1279", "bytes=1280-2559", "bytes=2560-3839", "bytes=3840-5119"]


def test_a_large_download_is_fetched_in_pieces_and_a_dropped_piece_resumes(tmp_path, monkeypatch):
    monkeypatch.setattr(localdb, "PART_SIZE", 1280)
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    server.cut[1280] = 500
    seen, slept = [], []
    target = tmp_path / "file"
    Fetcher(opener=server, sleep=slept.append).download(
        "https://x/f", target, sha256=f"sha256:{hashlib.sha256(data).hexdigest()}",
        progress=lambda done, total: seen.append((done, total)), connections=2)
    assert target.read_bytes() == data
    assert server.asked[0] == "bytes=0-0"
    assert sorted(server.asked[1:]) == sorted([*PARTS, "bytes=1780-2559"])
    assert (max(seen), slept) == ((len(data), len(data)), [])
    assert [p.name for p in tmp_path.iterdir()] == ["file"]


def test_a_piece_that_fails_is_resumed_alone_by_the_next_download(tmp_path, monkeypatch):
    monkeypatch.setattr(localdb, "PART_SIZE", 1280)
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    server.refused.add(PARTS[2])
    target = tmp_path / "file"
    with pytest.raises(SyncError, match="HTTP 503 after 2 attempts"):
        Fetcher(opener=server, retries=2, sleep=lambda s: None).download("https://x/f", target, connections=4)
    assert not target.exists()
    fetched = set(server.served)
    assert PARTS[2] not in fetched
    server.refused.clear()
    server.asked.clear()
    Fetcher(opener=server, sleep=lambda s: None).download("https://x/f", target, connections=4)
    assert target.read_bytes() == data
    assert sorted(server.asked) == sorted(["bytes=0-0", *(p for p in PARTS if p not in fetched)])
    assert [p.name for p in tmp_path.iterdir()] == ["file"]
    # Once a piece has failed, none is started: a server refusing them all is asked for those under way only.
    target.unlink()
    server.refused.update(PARTS)
    server.asked.clear()
    with pytest.raises(SyncError):
        Fetcher(opener=server, retries=2, sleep=lambda s: None).download("https://x/f", target, connections=2)
    assert server.asked[0] == "bytes=0-0" and set(server.asked[1:]) <= set(PARTS[:2])


def test_pieces_of_a_file_that_changed_are_not_joined(tmp_path, monkeypatch):
    monkeypatch.setattr(localdb, "PART_SIZE", 1280)
    data, changed = bytes(range(256)) * 20, bytes(range(255, -1, -1)) * 20
    server = RangeServer(data)
    server.refused.add(PARTS[2])
    target = tmp_path / "file"
    with pytest.raises(SyncError):
        Fetcher(opener=server, retries=1, sleep=lambda s: None).download("https://x/f", target, connections=4)
    # Changed between two syncs: the pieces kept are dropped.
    server.data, server.etag = changed, '"v2"'
    server.refused.clear()
    server.asked.clear()
    Fetcher(opener=server, sleep=lambda s: None).download("https://x/f", target, connections=4)
    assert target.read_bytes() == changed
    assert sorted(server.asked) == sorted(["bytes=0-0", *PARTS])
    # Changed during the download: the pieces asked by the old ETag come whole; it is fetched again, in one.
    target.unlink()
    server.asked.clear()

    def changing(url, headers):
        answer = server(url, headers)
        if headers.get("Range") == "bytes=0-0":
            server.data, server.etag = data, '"v3"'
        return answer
    Fetcher(opener=changing, sleep=lambda s: None).download("https://x/f", target, connections=2)
    assert target.read_bytes() == data
    assert (server.asked[0], server.asked[-1]) == ("bytes=0-0", None) and set(server.asked[1:-1]) <= set(PARTS)
    assert [p.name for p in tmp_path.iterdir()] == ["file"]


class Held:
    """A connection that sends its body in steps: so many bytes, then nothing until the step's event is set (or
    its function returns)."""

    def __init__(self, body: bytes, *steps):
        self.body, self.steps, self.at = body, list(steps), 0
        self.closed = threading.Event()

    def read(self, size=-1):
        while self.steps and self.at >= self.steps[0][0]:
            wait = self.steps.pop(0)[1]
            wait.wait(10) if isinstance(wait, threading.Event) else wait()
        end = min(self.steps[0][0] if self.steps else len(self.body), len(self.body),
                  len(self.body) if size < 0 else self.at + size)
        chunk, self.at = self.body[self.at:end], max(self.at, end)
        return chunk

    def close(self):
        self.closed.set()


def holding(server, held: dict):
    """``server``, with the ranges ``held`` maps to steps answered by a Held connection."""
    streams = {}

    def open_(url, headers):
        status, answer, stream = server(url, headers)
        if headers.get("Range") in held:
            streams[headers["Range"]] = Held(stream.read(), *held[headers["Range"]])
            return status, answer, streams[headers["Range"]]
        return status, answer, stream
    return open_, streams


@pytest.fixture
def quick_seconds(monkeypatch):
    """Pieces of 1280 bytes; a piece is fetched a second time once it has run 50 ms slower than the others (by
    then a held connection has sent what it sends: one with nothing yet would be asked again from the start)."""
    monkeypatch.setattr(localdb, "PART_SIZE", 1280)
    monkeypatch.setattr(localdb, "HEDGE_LEAST", 0.05)
    monkeypatch.setattr(localdb, "HEDGE_AFTER", 0.05)
    monkeypatch.setattr(localdb, "HEDGE_CHECK", 0.01)


def test_a_piece_held_up_at_the_end_is_fetched_again_and_taken_from_the_first_to_finish(tmp_path, quick_seconds):
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    release, moved = threading.Event(), threading.Event()
    piece = tmp_path / "file.4-of-4"

    def own_fetch_moves_on():
        moved.set()
        deadline = time.monotonic() + 10
        while piece.stat().st_size < 400 and time.monotonic() < deadline:
            time.sleep(0.005)
    # Its own fetch sends 100 bytes; the second fetch begins from there, and the own one sends 300 more before
    # the second sends anything.
    open_, streams = holding(server, {PARTS[3]: [(100, moved), (400, release)],
                                      "bytes=3940-5119": [(0, own_fetch_moves_on)]})
    target = tmp_path / "file"
    Fetcher(opener=open_, sleep=lambda s: None).download(
        "https://x/f", target, sha256=f"sha256:{hashlib.sha256(data).hexdigest()}", connections=2)
    assert target.read_bytes() == data
    # The rest is asked once more, after every piece has been started.
    assert sorted(server.asked[1:-1]) == PARTS and server.asked[-1] == "bytes=3940-5119"
    # The fetch that lost goes on until its connection sends again, and then writes nothing.
    release.set()
    assert streams[PARTS[3]].closed.wait(5)
    assert target.read_bytes() == data
    assert [p.name for p in tmp_path.iterdir()] == ["file"]


@pytest.mark.parametrize("held, sent, again, most", [
    # Each rest is less than half a piece: both are fetched again at once.
    ((2, 3), 700, 2, 2),
    # Either rest is most of a piece: the one is fetched again only once the other's second fetch is over.
    ((2, 3), 100, 2, 1),
    # More connections are idle, and the rest is small: a piece is fetched a second time over one of them.
    ((3,), 1000, 1, 1),
])
def test_pieces_are_fetched_again_at_once_as_far_as_their_rests_keep_within_a_piece(
        tmp_path, quick_seconds, held, sent, again, most):
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    release, gate = threading.Event(), threading.Event()
    open_, _ = holding(server, {PARTS[k]: [(sent, release)] for k in held})
    seconds, open_at_once = [], [0]

    def opener(url, headers):
        status, answer, stream = open_(url, headers)
        if headers["Range"] in ("bytes=0-0", *PARTS):
            return status, answer, stream
        # The first second fetch is held a while: one started meanwhile would be open with it.
        if not seconds:
            threading.Timer(0.3, gate.set).start()
        seconds.append(Held(stream.read(), (0, gate)))
        open_at_once[0] = max(open_at_once[0], sum(not s.closed.is_set() for s in seconds))
        return status, answer, seconds[-1]
    try:
        Fetcher(opener=opener, sleep=lambda s: None).download("https://x/f", tmp_path / "file", connections=4)
    finally:
        release.set()
    assert (tmp_path / "file").read_bytes() == data
    # No own fetch got further meanwhile: nothing was fetched twice.
    assert (len(seconds), open_at_once[0]) == (again, most)


def test_bytes_a_second_fetch_got_before_it_failed_count_as_fetched_for_nothing(tmp_path, quick_seconds):
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    release = threading.Event()
    open_, _ = holding(server, {PARTS[2]: [(100, release)], PARTS[3]: [(100, release)]})
    seconds = []

    def opener(url, headers):
        status, answer, stream = open_(url, headers)
        if headers["Range"] in ("bytes=0-0", *PARTS):
            return status, answer, stream
        # Closed after 200 bytes: 200 and either rest of 1180 make more than a piece.
        seconds.append(Held(stream.read()[:200]))
        return status, answer, seconds[-1]

    def let_go_once_another_would_have_started():
        deadline = time.monotonic() + 10
        while not seconds and time.monotonic() < deadline:
            time.sleep(0.005)
        if seconds:
            seconds[0].closed.wait(10)
        # Another second fetch, were it allowed, would start within HEDGE_CHECK of the first one's end.
        time.sleep(0.3)
        release.set()
    threading.Thread(target=let_go_once_another_would_have_started, daemon=True).start()
    Fetcher(opener=opener, sleep=lambda s: None).download("https://x/f", tmp_path / "file", connections=4)
    assert (tmp_path / "file").read_bytes() == data
    assert len(seconds) == 1


def test_a_piece_is_fetched_again_once_it_has_run_as_long_as_one_takes_at_the_others_speed(tmp_path, quick_seconds,
                                                                                         monkeypatch):
    monkeypatch.setattr(localdb, "HEDGE_AFTER", 30.0)
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    release = threading.Event()
    open_, _ = holding(server, {PARTS[3]: [(100, release)]})
    seconds = []

    def opener(url, headers):
        status, answer, stream = open_(url, headers)
        if headers["Range"] not in ("bytes=0-0", *PARTS):
            seconds.append(headers["Range"])
        return status, answer, stream
    # The other pieces took no time: the held one is fetched again after HEDGE_LEAST, long before this.
    threading.Timer(2.0, release.set).start()
    try:
        Fetcher(opener=opener, sleep=lambda s: None).download("https://x/f", tmp_path / "file", connections=4)
    finally:
        release.set()
    assert (tmp_path / "file").read_bytes() == data
    assert seconds == ["bytes=3940-5119"]


def test_second_fetches_fetch_no_more_than_a_piece_twice_in_all(tmp_path, quick_seconds):
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    release, moved = threading.Event(), {2: threading.Event(), 3: threading.Event()}
    seconds = []

    def opener(url, headers):
        status, answer, stream = server(url, headers)
        span = headers["Range"]
        if span in PARTS[2:]:
            return status, answer, Held(stream.read(), (100, moved[PARTS.index(span)]), (1000, release))
        if span in ("bytes=0-0", *PARTS):
            return status, answer, stream
        k = int(span[len("bytes="):].split("-")[0]) // 1280

        def own_fetch_gets_900_more():
            moved[k].set()
            deadline = time.monotonic() + 10
            while (tmp_path / f"file.{k + 1}-of-4").stat().st_size < 1000 and time.monotonic() < deadline:
                time.sleep(0.005)
        seconds.append(Held(stream.read(), (0, own_fetch_gets_900_more)))
        return status, answer, seconds[-1]

    def let_go_once_another_would_have_started():
        deadline = time.monotonic() + 10
        while not seconds and time.monotonic() < deadline:
            time.sleep(0.005)
        if seconds:
            seconds[0].closed.wait(10)
        # A second fetch for the other piece, were it allowed, would start within HEDGE_CHECK of the first one's end.
        time.sleep(0.3)
        for event in (*moved.values(), release):
            event.set()
    threading.Thread(target=let_go_once_another_would_have_started, daemon=True).start()
    Fetcher(opener=opener, sleep=lambda s: None).download("https://x/f", tmp_path / "file", connections=4)
    assert (tmp_path / "file").read_bytes() == data
    # 900 bytes of the first were fetched twice: the other's 1180 left would make more than a piece.
    assert len(seconds) == 1


def test_a_sync_stopped_during_a_second_fetch_resumes_the_piece_from_its_own_file(tmp_path, quick_seconds):
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    release = threading.Event()
    open_, streams = holding(server, {PARTS[3]: [(100, release)], "bytes=3940-5119": [(300, release)]})
    target = tmp_path / "file"

    def interrupt(done, total):
        # Ctrl-C once the second fetch has got further than the piece's own.
        if done >= 3 * 1280 + 400:
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        Fetcher(opener=open_, sleep=lambda s: None).download("https://x/f", target, progress=interrupt,
                                                             connections=2)
    # What the second fetch had is not kept, even while its connection is still open.
    assert not (tmp_path / "file.4-of-4.second").exists()
    release.set()
    assert len(streams) == 2 and all(s.closed.wait(5) for s in streams.values())
    # Neither wrote after the interrupt, and the second's bytes are not kept.
    assert sorted(p.name for p in tmp_path.iterdir()) == [*(f"file.{k}-of-4" for k in range(1, 5)), "file.parts"]
    assert (tmp_path / "file.4-of-4").read_bytes() == data[3840:3940]
    server.asked.clear()
    Fetcher(opener=server, sleep=lambda s: None).download(
        "https://x/f", target, sha256=f"sha256:{hashlib.sha256(data).hexdigest()}", connections=2)
    assert target.read_bytes() == data
    assert server.asked == ["bytes=0-0", "bytes=3940-5119"]
    assert [p.name for p in tmp_path.iterdir()] == ["file"]


def test_a_second_fetch_left_by_a_sync_killed_outright_is_not_added_to(tmp_path, quick_seconds):
    data = bytes(range(256)) * 20
    server = RangeServer(data)
    # As a sync killed outright leaves it: piece 4 begun, the others not, and a second fetch of piece 4 begun.
    (tmp_path / "file.parts").write_text(json.dumps({"total": 5120, "etag": '"v1"', "piece": 1280}), "utf-8")
    (tmp_path / "file.4-of-4").write_bytes(data[3840:3940])
    (tmp_path / "file.4-of-4.second").write_bytes(b"x" * 300)
    release = threading.Event()

    def open_(url, headers):
        status, answer, stream = server(url, headers)
        # Piece 4's own fetch (the first to ask for the rest of it) sends nothing; its second fetch finishes it.
        if headers["Range"] == "bytes=3940-5119" and server.asked.count("bytes=3940-5119") == 1:
            return status, answer, Held(stream.read(), (0, release))
        return status, answer, stream
    try:
        Fetcher(opener=open_, sleep=lambda s: None).download(
            "https://x/f", tmp_path / "file", sha256=f"sha256:{hashlib.sha256(data).hexdigest()}", connections=2)
    finally:
        release.set()
    assert (tmp_path / "file").read_bytes() == data
    assert sorted(server.asked) == sorted(["bytes=0-0", *PARTS[:3], "bytes=3940-5119", "bytes=3940-5119"])
    assert [p.name for p in tmp_path.iterdir()] == ["file"]


@pytest.mark.parametrize("ranges, size", [(False, 5120), (True, 1280)])
def test_a_file_is_fetched_in_one_when_the_server_sends_no_ranges_or_it_is_small(tmp_path, monkeypatch, ranges, size):
    monkeypatch.setattr(localdb, "PART_SIZE", 1280)
    data = bytes(range(256)) * 20
    server = RangeServer(data[:size], ranges)
    target = tmp_path / "file"
    Fetcher(opener=server, sleep=lambda s: None).download("https://x/f", target, connections=4)
    assert target.read_bytes() == data[:size]
    assert server.asked == ["bytes=0-0", None]


def java_db_layer(tmp_path, rows):
    path = tmp_path / "trivy-java.db"
    path.unlink(missing_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            "CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT);"
            "CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT,"
            " foreign key (artifact_id) references artifacts(id));"
            "CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1);")
        for number, (group, artifact, version, sha1) in enumerate(rows, 1):
            connection.execute("INSERT INTO artifacts VALUES (?, ?, ?)", (number, group, artifact))
            connection.execute("INSERT INTO indices VALUES (?, ?, ?, 'jar')", (number, version, bytes.fromhex(sha1)))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        archive.add(path, arcname="trivy-java.db")
    return buffer.getvalue()


BASE = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=20)


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def ghcr_routes(layer, digest=None, created=BASE, chunks=None):
    digest = digest or f"sha256:{hashlib.sha256(layer).hexdigest()}"
    manifest = {"schemaVersion": 2, "annotations": {"org.opencontainers.image.created": iso(created)},
                "layers": [{"mediaType": localdb.JAVA_DB_LAYER, "digest": digest, "size": len(layer)}]}
    return {"ghcr.io/token": {"token": "anonymous"}, "/manifests/1": manifest, "/blobs/sha256:": Served(layer),
            **central_routes(chunks or {1: index_chunk(created - timedelta(days=30))})}


def index_chunk(cut, *records):
    """A chunk of the Central index in the Maven Indexer format."""
    out = io.BytesIO()
    out.write(struct.pack(">bq", 1, int(cut.timestamp() * 1000)))
    for fields in records:
        out.write(struct.pack(">i", len(fields)))
        for name, value in fields.items():
            name, value = name.encode(), value.encode()
            out.write(struct.pack(">bH", 0, len(name)) + name + struct.pack(">i", len(value)) + value)
    return gzip.compress(out.getvalue())


def published(group, artifact, version, sha1, classifier="NA", extension="jar", in_u=True):
    u = f"{group}|{artifact}|{version}|{classifier}" + (f"|{extension}" if in_u else "")
    return {"u": u, "i": f"jar|1791860776000|1000|0|0|0|{extension}", "m": "1791860776000", "1": sha1}


def checked_long_ago(db):
    """As if Central's index was last looked at eight days ago."""
    state = json.loads((db.directory / "state.json").read_text())
    state["maven-hashes"]["checked"] = iso(datetime.now(timezone.utc) - timedelta(days=8))
    (db.directory / "state.json").write_text(json.dumps(state))


class Limited(Served):
    """A chunk that can be dated, but whose download the server refuses for a day."""

    refused = 0

    def respond(self, headers):
        if headers.get("Range") == "bytes=0-4095":
            return super().respond(headers)
        type(self).refused += 1
        return 429, b"", {"Retry-After": "86400"}


class HeadOnly(Served):
    """A chunk that may only be dated from its first bytes, never downloaded."""

    def respond(self, headers):
        assert headers.get("Range") == "bytes=0-4095", "an old chunk was downloaded"
        return super().respond(headers)


def central_routes(chunks, chain="7", listed=None):
    numbers = sorted(listed or chunks, reverse=True)
    properties = (f"#Thu Oct 22 16:29:55 UTC 2026\nnexus.index.chain-id={chain}\n"
                  f"nexus.index.last-incremental={numbers[0]}\n"
                  + "".join(f"nexus.index.incremental-{i}={n}\n" for i, n in enumerate(numbers)))
    return {"nexus-maven-repository-index.properties": properties.encode(),
            **{f"nexus-maven-repository-index.{n}.gz": c if isinstance(c, Served) else Served(c)
               for n, c in chunks.items()}}


def test_maven_hashes_sync_skips_an_unchanged_release(tmp_path):
    sha1 = hashlib.sha1(PUBLISHED).hexdigest()
    layer = java_db_layer(tmp_path, [("org.example", "lib", "1.0", sha1)])
    db = LocalDb(tmp_path / "db")
    assert db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport(ghcr_routes(layer))), log=lambda m: None) == {
        "maven-hashes": "downloaded 1 jar hashes; no new additions on Central"}
    assert db.coordinates_for_sha1(sha1) == [("org.example", "lib", "1.0")]
    assert db.state["maven-hashes"]["data_as_of"] == iso(BASE)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    kept = db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport({"": never})), log=lambda m: None)
    assert kept["maven-hashes"] == f"base of {iso(BASE)[:10]} kept (downloaded again after 180 days); " \
                                   f"Central's additions checked on {today} (again after 7 days)"
    again = ScriptedTransport({**ghcr_routes(layer), "/blobs/": never, ".index/": never})
    assert db.sync(["maven-hashes"], hashes_every=0, fetcher=fetcher(again), log=lambda m: None) == {
        "maven-hashes": f"up to date; Central's additions checked on {today} (again after 7 days)"}
    checked_long_ago(db)
    assert db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport({**ghcr_routes(layer), "ghcr.io": never})),
                   log=lambda m: None)["maven-hashes"].endswith("; no new additions on Central")


def test_maven_hashes_download_asks_for_a_new_token_when_resuming(tmp_path):
    sha1 = "11" * 20
    layer = java_db_layer(tmp_path, [("g", "a", "1", sha1)])
    scripted = opener(ScriptedTransport(ghcr_routes(layer)))
    issued, spent = [], set()

    def open_(url, headers):
        if "ghcr.io/token" in url:
            issued.append(f"t{len(issued)}")
            return 200, {}, io.BytesIO(json.dumps({"token": issued[-1]}).encode())
        if "/blobs/" not in url:
            return scripted(url, headers)
        token = headers["Authorization"]
        if token in spent:
            return 401, {}, io.BytesIO(b"")
        spent.add(token)
        start = int(headers["Range"][len("bytes="):].partition("-")[0]) if "Range" in headers else 0
        piece = io.BytesIO(layer[start:start + len(layer) // 3 + 1])
        if start:
            return 206, {"Content-Range": f"bytes {start}-{len(layer) - 1}/{len(layer)}"}, piece
        return 200, {"Content-Length": str(len(layer))}, piece

    db = LocalDb(tmp_path / "db")
    assert db.sync(["maven-hashes"], fetcher=Fetcher(opener=open_, sleep=lambda s: None), log=lambda m: None) == {
        "maven-hashes": "downloaded 1 jar hashes; no new additions on Central"}
    assert db.coordinates_for_sha1(sha1) == [("g", "a", "1")]


def test_maven_hashes_rejects_a_corrupted_download(tmp_path):
    layer = java_db_layer(tmp_path, [("g", "a", "1", "00" * 20)])
    db = LocalDb(tmp_path / "db")
    outcome = db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport(ghcr_routes(layer, "sha256:" + "0" * 64))),
                      log=lambda m: None)
    assert "does not match" in outcome["maven-hashes"]
    assert not db.has("maven-hashes")


def test_central_additions_extend_the_base(tmp_path):
    base_jar, early, late, native, newest = ("1" * 40, "2" * 40, "3" * 40, "4" * 40, "5" * 40)
    layer = java_db_layer(tmp_path, [("g", "base", "1", base_jar), ("g", "native", "1", "7" * 40),
                                     ("g", "native", "1", "8" * 40)])
    chunks = {
        10: HeadOnly(index_chunk(BASE - timedelta(days=9), published("g", "older", "1", "9" * 40))),
        # Cut before the base, but within the week it may have missed.
        11: index_chunk(BASE - timedelta(days=3), published("g", "early", "1", early),
                        published("g", "base", "1", base_jar)),
        12: index_chunk(BASE + timedelta(days=4), published("g", "late", "2", native, classifier="linux-x86_64"),
                        published("g", "late", "2", late, in_u=False),
                        published("g", "late", "2", "6" * 40, extension="pom"),
                        published("g", "late", "2", "a" * 40, classifier="sources"),
                        {"del": "g|gone|1|NA|jar"}),
    }
    db = LocalDb(tmp_path / "db")
    transport = ScriptedTransport(ghcr_routes(layer, chunks=chunks))
    assert db.sync(["maven-hashes"], fetcher=fetcher(transport), log=lambda m: None) == {
        "maven-hashes": "downloaded 3 jar hashes; applied Central's additions #11-#12"}
    assert db.coordinates_for_sha1(early) == [("g", "early", "1")]
    assert db.coordinates_for_sha1(base_jar) == [("g", "base", "1")]
    assert db.coordinates_for_sha1(native) == [("g", "late", "2")]
    assert db.coordinates_for_sha1(late) == [("g", "late", "2")]
    assert [db.coordinates_for_sha1(x * 40) for x in "96a"] == [[], [], []]
    assert [db.maven_groups(a) for a in ("base", "early", "nothing")] == [["g"], ["g"], []]
    assert LocalDb(tmp_path / "none").maven_groups("base") == []
    entry = db.state["maven-hashes"]
    assert (entry["chunk"], entry["chain"], entry["data_as_of"]) == (12, "7", iso(BASE + timedelta(days=4)))
    assert (entry["base_records"], entry["recent_records"], entry["records"]) == (3, 4, 7)

    chunks[13] = index_chunk(BASE + timedelta(days=11), published("g", "newest", "3", newest))
    checked_long_ago(db)
    later = ScriptedTransport({**central_routes({13: chunks[13]}, listed=[13, 12, 11, 10]), "": never})
    assert LocalDb(tmp_path / "db").sync(["maven-hashes"], fetcher=fetcher(later), log=lambda m: None) == {
        "maven-hashes": f"base of {iso(BASE)[:10]} kept (downloaded again after 180 days); "
                        "applied Central's additions #13-#13"}
    reopened = LocalDb.open(tmp_path / "db")
    assert reopened.coordinates_for_sha1(newest) == [("g", "newest", "3")]
    assert reopened.state["maven-hashes"]["records"] == 8
    checked_long_ago(reopened)
    quiet = ScriptedTransport({**central_routes({}, listed=[13, 12]), "": never})
    assert reopened.sync(["maven-hashes"], fetcher=fetcher(quiet), log=lambda m: None)["maven-hashes"].endswith(
        "no new additions on Central")
    assert reopened.status()[3]["bytes"] > (tmp_path / "db" / "maven-hashes.db").stat().st_size


def test_copy_installed_before_additions_existed_catches_up(tmp_path):
    layer = java_db_layer(tmp_path, [("g", "base", "1", "1" * 40)])
    db = LocalDb(tmp_path / "db")
    db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport(ghcr_routes(layer))), log=lambda m: None)
    entry = db.state["maven-hashes"]
    db.state["maven-hashes"] = {"digest": entry["digest"], "data_as_of": entry["data_as_of"], "records": 1,
                                "downloaded": entry["synced"], "synced": entry["synced"]}
    db._write_state()
    chunks = {5: HeadOnly(index_chunk(BASE - timedelta(days=20))),
              6: index_chunk(BASE + timedelta(days=2), published("g", "new", "1", "2" * 40))}
    outcome = db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport({**central_routes(chunks), "ghcr.io": never})),
                      log=lambda m: None)
    assert outcome["maven-hashes"].endswith("applied Central's additions #6-#6")
    assert db.coordinates_for_sha1("2" * 40) == [("g", "new", "1")]
    assert (db.state["maven-hashes"]["base_records"], db.state["maven-hashes"]["records"]) == (1, 2)


@pytest.mark.parametrize("change", ["restarted", "gap", "truncated", "base too old", "no longer served"])
def test_additions_that_cannot_be_applied_leave_the_copy_as_it_was(tmp_path, change):
    layer = java_db_layer(tmp_path, [("g", "base", "1", "1" * 40)])
    first = {2: HeadOnly(index_chunk(BASE - timedelta(days=30))),
             3: index_chunk(BASE + timedelta(days=1), published("g", "a", "1", "2" * 40))}
    db = LocalDb(tmp_path / "db")
    db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport(ghcr_routes(layer, chunks=first))), log=lambda m: None)
    checked_long_ago(db)
    before = dict(LocalDb(tmp_path / "db").state["maven-hashes"])
    following = index_chunk(BASE + timedelta(days=8), published("g", "b", "1", "3" * 40))
    routes = {"restarted": central_routes({4: following}, chain="8", listed=[4, 3]),
              "gap": central_routes({9: following}, listed=[9, 8, 7, 6, 5]),
              "truncated": central_routes({4: Served(following[:-10])}, listed=[4, 3]),
              "no longer served": {**central_routes({5: following}, listed=[5, 4, 3]), "index.4.gz": None}}
    if change == "base too old":
        db.state["maven-hashes"] = {k: v for k, v in before.items() if k not in ("chunk", "chain")}
        db._write_state()
        before = dict(db.state["maven-hashes"])
        routes[change] = central_routes({4: following})
    outcome = db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport({**routes[change], "": never})),
                      log=lambda m: None)["maven-hashes"]
    assert outcome.startswith("failed")
    if change != "truncated":
        assert "binwitness db sync maven-hashes --full" in outcome
    assert LocalDb(tmp_path / "db").state["maven-hashes"] == before
    assert db.coordinates_for_sha1("3" * 40) == []
    assert db.coordinates_for_sha1("1" * 40) == [("g", "base", "1")]


def test_a_new_base_replaces_the_additions(tmp_path):
    layer = java_db_layer(tmp_path, [("g", "base", "1", "1" * 40)])
    chunks = {2: HeadOnly(index_chunk(BASE - timedelta(days=30))),
              3: index_chunk(BASE + timedelta(days=1), published("g", "added", "1", "2" * 40))}
    db = LocalDb(tmp_path / "db")
    db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport(ghcr_routes(layer, chunks=chunks))), log=lambda m: None)
    assert db.coordinates_for_sha1("2" * 40) == [("g", "added", "1")]
    rebuilt = java_db_layer(tmp_path, [("g", "rebuilt", "2", "3" * 40)])
    newer = BASE + timedelta(days=10)
    transport = ScriptedTransport(ghcr_routes(rebuilt, created=newer, chunks={2: chunks[2], 3: HeadOnly(chunks[3])}))
    assert db.sync(["maven-hashes"], full=True, fetcher=fetcher(transport), log=lambda m: None) == {
        "maven-hashes": "downloaded 1 jar hashes; no new additions on Central"}
    assert db.coordinates_for_sha1("2" * 40) == []
    assert db.coordinates_for_sha1("3" * 40) == [("g", "rebuilt", "2")]
    entry = db.state["maven-hashes"]
    assert (entry["base_as_of"], entry["data_as_of"], entry["records"], entry["chunk"]) == (iso(newer), iso(newer), 1, 3)


def test_a_new_base_is_kept_when_its_additions_fail(tmp_path):
    layer = java_db_layer(tmp_path, [("g", "base", "1", "1" * 40)])
    chunks = {2: HeadOnly(index_chunk(BASE - timedelta(days=30))),
              3: index_chunk(BASE + timedelta(days=1), published("g", "added", "1", "2" * 40))}
    db = LocalDb(tmp_path / "db")
    db.sync(["maven-hashes"], fetcher=fetcher(ScriptedTransport(ghcr_routes(layer, chunks=chunks))), log=lambda m: None)
    rebuilt = java_db_layer(tmp_path, [("g", "rebuilt", "2", "3" * 40)])
    routes = ghcr_routes(rebuilt, created=BASE + timedelta(days=10))
    routes["nexus-maven-repository-index.properties"] = (503, b"")
    assert db.sync(["maven-hashes"], full=True, fetcher=fetcher(ScriptedTransport(routes)),
                   log=lambda m: None)["maven-hashes"].startswith("failed")
    assert db.coordinates_for_sha1("2" * 40) == []
    assert db.state["maven-hashes"]["chunk"] is None
    later = ScriptedTransport({**central_routes({2: chunks[2], 3: HeadOnly(chunks[3])}), "": never})
    assert db.sync(["maven-hashes"], fetcher=fetcher(later), log=lambda m: None)["maven-hashes"].endswith(
        "no new additions on Central")
    assert db.coordinates_for_sha1("3" * 40) == [("g", "rebuilt", "2")]


def test_rate_limit_stops_at_once_and_keeps_what_was_applied(tmp_path):
    layer = java_db_layer(tmp_path, [("g", "base", "1", "1" * 40)])
    chunks = {2: HeadOnly(index_chunk(BASE - timedelta(days=30))),
              3: index_chunk(BASE + timedelta(days=1), published("g", "a", "1", "2" * 40)),
              4: Limited(index_chunk(BASE + timedelta(days=5)))}
    db = LocalDb(tmp_path / "db")
    transport = ScriptedTransport(ghcr_routes(layer, chunks=chunks))
    outcome = db.sync(["maven-hashes"], fetcher=fetcher(transport), log=lambda m: None)["maven-hashes"]
    assert outcome.startswith("failed") and "try again in 24.0 hours" in outcome
    assert Limited.refused == 1
    assert db.state["maven-hashes"]["chunk"] == 3
    assert db.coordinates_for_sha1("2" * 40) == [("g", "a", "1")]
    chunks[4] = index_chunk(BASE + timedelta(days=8), published("g", "b", "1", "3" * 40))
    later = ScriptedTransport({**central_routes({4: chunks[4]}, listed=[4, 3, 2]), "": never})
    assert db.sync(["maven-hashes"], fetcher=fetcher(later), log=lambda m: None)["maven-hashes"].endswith(
        "applied Central's additions #4-#4")
    assert db.coordinates_for_sha1("3" * 40) == [("g", "b", "1")]


# ---- scanning with local datasets ----------------------------------------------------------------------

def installed(tmp_path, hashes):
    db = LocalDb(tmp_path / "db")
    catalog = {"dateReleased": "2026-10-28", "vulnerabilities": [{"cveID": "CVE-2023-0001", "dateAdded": "2024-02-02"}]}
    transport = ScriptedTransport({"/Maven/all.zip": osv_zip(*RECORDS.values()), "known_exploited": catalog,
                                   **ghcr_routes(java_db_layer(tmp_path, hashes))})
    outcomes = db.sync(expand(["java"]), fetcher=fetcher(transport), log=lambda m: None)
    assert not any(o.startswith("failed") for o in outcomes.values())
    return LocalDb.open(tmp_path / "db")


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "bundle.zip"
    path.write_bytes(make_zip({"lib/lib-1.0.jar": PUBLISHED, "lib/netty-all-4.1.54.Final.jar": NETTY_ALL,
                               "lib/service-1.0-SNAPSHOT.jar": make_jar("com.acme", "service", "1.0-SNAPSHOT"),
                               "lib/private.jar": make_zip({"x/Y.class": b"\xca\xfe"})}))
    return path


def test_local_lookup_needs_no_network(tmp_path, bundle):
    db = installed(tmp_path, [("org.example", "lib", "1.0", hashlib.sha1(PUBLISHED).hexdigest()),
                              ("io.netty", "netty-all", "4.1.54.Final", hashlib.sha1(NETTY_ALL).hexdigest())])
    transport = ScriptedTransport({"": never})
    net = Net(cache_dir=tmp_path / "cache", offline=True, transport=transport)
    result = scan([bundle], net, Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None, db=db)
    assert transport.calls == []
    lib = next(c for c in result["components"] if c["name"] == "org.example:lib")
    assert lib["confidence"] == "exact" and "local copy" in lib["evidence"][0]["method"]
    assert lib["vulnerabilities"] == ["CVE-2023-0001"]
    assert result["vulnerabilities"]["CVE-2023-0001"]["kev_date_added"] == "2024-02-02"
    assert set(result["data_sources"]["local"]) == {"osv-maven", "kev", "maven-hashes"}
    assert result["options"]["lookup"] == "local"
    assert not [w for w in result["warnings"] if "license lookup failed" in w]
    # Absent from the index is not the same as unknown to every registry; local mode cannot tell.
    assert [u["reason"] for u in result["unidentified"]] == [OFFLINE_UNKNOWN]
    # Licenses are not in the datasets; the warnings say which results are missing and where they come from.
    unknown = [c for c in result["components"] if c["license"]["family"] == "unknown"]
    assert unknown
    assert f"license unknown for {len(unknown)} components: the registry's answer is not in the cache, and this " \
           "scan does not go online" in result["warnings"]
    offline = next(w for w in result["warnings"] if w.startswith("offline: "))
    hosts = dict(part.rsplit(" ", 1) for part in offline.split("(", 1)[1].rstrip(")").split(", "))
    assert sum(map(int, hosts.values())) == int(offline.split()[1])
    # License lookups, and the version list of netty-codec-http, which the hash index has no jar of.
    assert set(hosts) == {"api.deps.dev", "repo1.maven.org"}
    # The index holds lib 1.0 only, so the 1.1 that the advisory calls fixed may well be published since.
    assert lib["upgrade"]["verdict"] == "unverified" and "(1.1) is not in the local hash index" in lib["upgrade"]["reason"]
    codec = next(c for c in result["components"] if c["name"] == "io.netty:netty-codec-http")
    assert codec["upgrade"]["verdict"] == "unverified" and "offline" in codec["upgrade"]["reason"]
    assert result["summary"]["incomplete"]["upgrade_versions_not_checked"] == 2
    # The index is installed: the jar it lacks is not blamed on a missing dataset.
    assert not [w for w in result["warnings"] if "db sync maven-hashes" in w]
    assert "db sync maven-hashes" not in render_summary(result)


def test_an_offline_scan_without_the_hash_index_says_how_to_identify_jars_locally(tmp_path, bundle):
    db = installed(tmp_path, [])
    db.remove(["maven-hashes"])
    db = LocalDb.open(tmp_path / "db")
    net = Net(cache_dir=tmp_path / "cache", offline=True, transport=ScriptedTransport({"": never}))
    result = scan([bundle], net, Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None, db=db)
    assert result["options"]["lookup"] == "local"
    # The jars that declare their coordinates are named all the same; the one that declares none is not.
    assert [u["filename"] for u in result["unidentified"]] == ["private.jar"]
    assert ("1 jar not identified offline: the Maven Central hash index is not installed; `binwitness db sync "
            "maven-hashes` installs it, and an offline scan then identifies the published ones") in result["warnings"]
    assert "tip          1 jar not identified offline: the Maven Central hash index is not installed" \
        in render_summary(result)
    # Replaying an online scan's cache: the index would not be asked.
    replay = scan([bundle], net, Options(first_party_groups=("com.acme",), scan_js=False, lookup="online"),
                  log=lambda m: None)
    assert replay["unidentified"] and not [w for w in replay["warnings"] if "db sync maven-hashes" in w]
    assert "db sync maven-hashes" not in render_summary(replay)


def test_auto_lookup_asks_online_only_for_what_the_index_lacks(tmp_path, bundle):
    db = installed(tmp_path, [("org.example", "lib", "1.0", hashlib.sha1(PUBLISHED).hexdigest())])
    transport = ScriptedTransport(routes(querybatch=never, known_exploited=never))
    net = Net(cache_dir=tmp_path / "cache", transport=transport, sleep=lambda s: None)
    result = scan([bundle], net, Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None, db=db)
    hash_lookups = [url for _, url, _ in transport.calls if "hash.value=" in url]
    indexed = urllib.parse.quote(base64.b64encode(hashlib.sha1(PUBLISHED).digest()).decode(), safe="")
    assert len(hash_lookups) == 2 and not any(indexed in url for url in hash_lookups)  # netty-all, private.jar
    assert {c["name"] for c in result["components"]} >= {"org.example:lib", "io.netty:netty-all"}
    assert result["options"]["lookup"] == "auto"


def test_local_and_online_vulnerability_answers_agree(tmp_path, bundle):
    online = scan([bundle], Net(cache_dir=tmp_path / "online", transport=ScriptedTransport(routes()), sleep=lambda s: None),
                  Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None)
    db = installed(tmp_path, [])
    local = scan([bundle], Net(cache_dir=tmp_path / "local", transport=ScriptedTransport(routes()), sleep=lambda s: None),
                 Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None, db=db)
    assert online["vulnerabilities"].keys() == local["vulnerabilities"].keys() != set()
    assert ({c["purl"]: c["vulnerabilities"] for c in online["components"]}
            == {c["purl"]: c["vulnerabilities"] for c in local["components"]})


def test_stale_datasets_are_reported(tmp_path):
    db = installed(tmp_path, [])
    db.kev()
    assert db.stale() == []
    assert "kev was last synced 10 days ago" in db.stale(now=time.time() + 10 * 86400)[0]


def test_cli_db_commands(tmp_path, capsys):
    assert main(["db", "sync", "--db-dir", str(tmp_path)]) == 2
    assert "osv-maven" in capsys.readouterr().err
    assert main(["db", "sync", "bogus", "--db-dir", str(tmp_path)]) == 2
    assert main(["db", "status", "--db-dir", str(tmp_path)]) == 0
    assert "not installed" in capsys.readouterr().out


def test_cli_db_status_tells_what_the_next_sync_will_do(tmp_path, capsys):
    db = installed(tmp_path, [])
    directory = str(tmp_path / "db")
    assert main(["db", "status", "--db-dir", directory]) == 0
    out = capsys.readouterr().out
    base = BASE.strftime("%Y-%m-%d")
    assert f"base {base}, replaced after {(BASE + timedelta(days=180)):%Y-%m-%d}" in out
    assert f"additions up to #{db.state['maven-hashes']['chunk']} (0 records), checked {localdb._now()[:10]}" in out
    assert "run `binwitness db sync`" not in out and "nothing installed" not in out
    # A copy installed before additions existed, last synced a while ago.
    state = json.loads((tmp_path / "db" / "state.json").read_text())
    for key in ("base_as_of", "chunk", "checked"):
        state["maven-hashes"].pop(key)
    state["kev"]["synced"] = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat(timespec="seconds")
    (tmp_path / "db" / "state.json").write_text(json.dumps(state))
    assert main(["db", "status", "--db-dir", directory, "--hashes-every", "30"]) == 0
    out = capsys.readouterr().out
    assert "additions not applied yet; the next sync applies them" in out
    assert f"replaced after {(datetime.fromisoformat(state['maven-hashes']['data_as_of'][:19]) + timedelta(days=30)):%Y-%m-%d}" in out
    assert "last synced more than 7 days ago: kev; run `binwitness db sync`" in out


def test_an_offline_scan_counts_the_scripts_it_could_not_look_up(tmp_path):
    db = installed(tmp_path, [])
    delivery = tmp_path / "site.zip"
    delivery.write_bytes(make_zip({"static/js/widget.js": b"(function(){var a=1;})();\n" * 50,
                                   "static/js/other.js": b"(function(){var b=2;})();\n" * 50}))
    transport = ScriptedTransport({"": never})
    net = Net(cache_dir=tmp_path / "cache", offline=True, transport=transport)
    result = scan([delivery], net, Options(), log=lambda m: None, db=db)
    assert transport.calls == []
    assert not [w for w in result["warnings"] if w.startswith("script lookup failed")]
    assert result["summary"]["incomplete"]["scripts_not_looked_up"] == 2
    assert sorted(result["unmatched_scripts"]) == ["site.zip!/static/js/other.js", "site.zip!/static/js/widget.js"]
    offline = next(w for w in result["warnings"] if w.startswith("offline: "))
    assert "data.jsdelivr.com 2" in offline


def test_cli_offline_online_replays_the_cache_without_datasets(tmp_path):
    db = installed(tmp_path, [])
    jar = tmp_path / "x.jar"
    jar.write_bytes(make_zip({"x/Y.class": b"\xca\xfe"}))
    common = [str(jar), "--offline", "--no-licenses", "--cache-dir", str(tmp_path / "cache"), "--db-dir", str(db.directory)]
    main(["scan", *common, "-o", str(tmp_path / "replay"), "--lookup", "online"])
    main(["scan", *common, "-o", str(tmp_path / "local")])
    replay = json.loads((tmp_path / "replay" / "binwitness.json").read_text())
    local = json.loads((tmp_path / "local" / "binwitness.json").read_text())
    assert (replay["options"]["lookup"], replay["data_sources"]["local"]) == ("online", {})
    # No findings, so the KEV catalog was not consulted.
    assert local["options"]["lookup"] == "local" and set(local["data_sources"]["local"]) == {"maven-hashes"}


def test_default_dataset_dir_is_not_a_cache_shard(monkeypatch, tmp_path):
    monkeypatch.delenv("BINWITNESS_DB", raising=False)
    monkeypatch.setenv("BINWITNESS_CACHE", str(tmp_path))
    first = localdb.default_db_dir().relative_to(tmp_path).parts[0]
    assert len(first) != 2 or not all(c in "0123456789abcdef" for c in first)


# ---- one file, several coordinates ---------------------------------------------------------------------

class OneCoordinateIndex:
    """The local index as Trivy builds it: each file under a single coordinate, so an artifact whose file was
    republished unchanged has no file for that version."""

    def __init__(self, entries, versions=None):
        self.entries, self.versions = entries, versions or {}

    def has(self, name):
        return name == "maven-hashes"

    def coordinates_for_sha1(self, sha1):
        return [self.entries[sha1]] if sha1 in self.entries else []

    def maven_groups(self, artifact):
        return sorted({group for group, other in self.versions if other == artifact})

    def maven_versions(self, group, artifact):
        return list(self.versions.get((group, artifact), []))


def deps_dev_answer(*coordinates):
    return {"results": [{"version": {"versionKey": {"system": "MAVEN", "name": f"{g}:{a}", "version": v},
                                     "licenses": ["Apache-2.0"]}} for g, a, v in coordinates]}


REPUBLISHED = "81" * 20
NETBEANS = ("org.netbeans.external", "org-apache-commons-io", "RELEASE113")
COMMONS_IO = ("commons-io", "commons-io", "2.6")
INDEX = OneCoordinateIndex({REPUBLISHED: NETBEANS}, {
    NETBEANS[:2]: ["RELEASE90", "RELEASE113"], COMMONS_IO[:2]: ["2.5", "2.7"],
    ("org.lucee", "commons-io"): ["2.4.0", "2.6.0", "2.8.0"]})


def quiet_net(tmp_path, offline=False):
    return Net(cache_dir=tmp_path / "cache", offline=offline, transport=ScriptedTransport({"": never}),
               sleep=lambda s: None)


def test_a_republished_jar_takes_the_coordinates_it_declares_when_the_index_has_no_file_under_them(tmp_path):
    net = quiet_net(tmp_path)
    hit = maven.lookup_hash(net, REPUBLISHED, "commons-io-2.6.jar", INDEX, COMMONS_IO)
    assert (hit["coordinate"], hit["named_by"], hit["alternatives"]) == (COMMONS_IO, "pom.properties", [NETBEANS])
    # Renamed, it still declares them.
    assert maven.lookup_hash(net, REPUBLISHED, "io.jar", INDEX, COMMONS_IO)["coordinate"] == COMMONS_IO
    # A file for 2.6 under commons-io is another file than this one, which is then NetBeans' own.
    taken = OneCoordinateIndex(INDEX.entries, {**INDEX.versions, COMMONS_IO[:2]: ["2.5", "2.6", "2.7"]})
    hit = maven.lookup_hash(net, REPUBLISHED, "commons-io-2.6.jar", taken, COMMONS_IO)
    assert (hit["coordinate"], "named_by" in hit) == (NETBEANS, False)
    # Coordinates the index does not know at all are not taken on the jar's word.
    unknown = OneCoordinateIndex(INDEX.entries, {NETBEANS[:2]: ["RELEASE113"]})
    assert maven.lookup_hash(net, REPUBLISHED, "commons-io-2.6.jar", unknown, COMMONS_IO)["coordinate"] == NETBEANS
    # Nor the version of the project's own release in its pom.properties, which lacks a variant suffix or
    # names a snapshot.
    own = ("com.example", "driver", "7.4.1.jre8")
    index = OneCoordinateIndex({REPUBLISHED: own}, {own[:2]: ["7.4.0.jre8", "7.4.1.jre8", "7.4.1.jre11"]})
    for version in ("7.4.1", "7.4.1-SNAPSHOT"):
        hit = maven.lookup_hash(net, REPUBLISHED, "driver-7.4.1.jre8.jar", index, (*own[:2], version))
        assert (hit["coordinate"], "named_by" in hit) == (own, False)
    # Nor are those of a library the jar merely carries: they neither name the file nor the indexed artifact.
    carried = ("org.example", "inner-lib", "1.0")
    inside = OneCoordinateIndex(INDEX.entries, {**INDEX.versions, carried[:2]: ["0.9", "1.1"]})
    assert maven.lookup_hash(net, REPUBLISHED, "bundle.jar", inside, carried)["coordinate"] == NETBEANS
    assert net.offline_misses == 0


def test_the_index_coordinate_that_names_the_file_needs_no_request(tmp_path):
    hit = maven.lookup_hash(quiet_net(tmp_path), REPUBLISHED, "org-apache-commons-io-RELEASE113.jar", INDEX)
    assert (hit["coordinate"], hit["source"]) == (NETBEANS, "Maven Central index, local copy")


def test_a_cached_registry_answer_does_not_change_the_coordinates_a_local_scan_gives(tmp_path):
    online = Net(cache_dir=tmp_path / "cache", sleep=lambda s: None, transport=ScriptedTransport(
        {"api.deps.dev": deps_dev_answer(("org.lucee", "commons-io", "2.6.0"), COMMONS_IO, NETBEANS)}))
    assert maven.lookup_hash(online, REPUBLISHED, "io.jar")["coordinate"] == COMMONS_IO
    for cache in ("cache", "empty"):
        offline = Net(cache_dir=tmp_path / cache, offline=True, transport=ScriptedTransport({"": never}))
        for filename in ("commons-io-2.6.jar", "io.jar"):
            assert maven.lookup_hash(offline, REPUBLISHED, filename, INDEX, COMMONS_IO)["coordinate"] == COMMONS_IO
        assert maven.lookup_hash(offline, REPUBLISHED, "commons-io-2.6.jar", INDEX)["coordinate"] == COMMONS_IO
        assert maven.lookup_hash(offline, REPUBLISHED, "io.jar", INDEX)["coordinate"] == NETBEANS
        assert offline.offline_misses == 0


def test_offline_finds_in_the_cache_what_the_index_lacks(tmp_path):
    elsewhere = "a2" * 20
    online = Net(cache_dir=tmp_path / "cache", sleep=lambda s: None, transport=ScriptedTransport(
        {"api.deps.dev": deps_dev_answer(("com.android.tools", "r8", "3.3.75"))}))
    maven.lookup_hash(online, elsewhere, "r8-3.3.75.jar")
    offline = Net(cache_dir=tmp_path / "cache", offline=True, transport=ScriptedTransport({"": never}))
    assert maven.lookup_hash(offline, elsewhere, "r8-3.3.75.jar", INDEX)["coordinate"] == (
        "com.android.tools", "r8", "3.3.75")


def test_the_jar_s_own_coordinate_names_the_original_of_a_republished_file(tmp_path):
    shared = "c3" * 20
    transport = ScriptedTransport({"api.deps.dev": deps_dev_answer(("org.example.mirror", "json-lib", "2.4"),
                                                                   ("net.sf.json-lib", "json-lib", "2.4"))})
    net = Net(cache_dir=tmp_path / "cache", transport=transport, sleep=lambda s: None)
    original = ("net.sf.json-lib", "json-lib", "2.4")
    assert maven.lookup_hash(net, shared, "json-lib-2.4-jdk15.jar", declared=original)["coordinate"] == original
    # The index filed it under the republisher, whose name fits the file just as well.
    index = OneCoordinateIndex({shared: ("org.example.mirror", "json-lib", "2.4")},
                               {("org.example.mirror", "json-lib"): ["2.4"], original[:2]: ["2.3"]})
    quiet = quiet_net(tmp_path / "other")
    assert maven.lookup_hash(quiet, shared, "json-lib-2.4-jdk15.jar", index, original)["coordinate"] == original
    agreeing = OneCoordinateIndex({shared: original}, {original[:2]: ["2.3", "2.4"]})
    assert maven.lookup_hash(quiet, shared, "json-lib-2.4-jdk15.jar", agreeing, original)["coordinate"] == original


BOUNCY = "b1" * 20
OLD_BOUNCY = ("bouncycastle", "bcprov-jdk14", "138")
BOUNCY_LINES = {OLD_BOUNCY[:2]: ["124", "136", "138", "139", "140"],
                ("org.bouncycastle", "bcprov-jdk14"): ["1.43", "1.44", "1.86"],
                ("org.codehaus.xfire", "bcprov-jdk14"): ["133"]}


def test_a_file_name_names_the_original_whose_version_the_index_has_no_file_for(tmp_path):
    net = quiet_net(tmp_path, offline=True)
    index = OneCoordinateIndex({BOUNCY: OLD_BOUNCY}, BOUNCY_LINES)
    hit = maven.lookup_hash(net, BOUNCY, "bcprov-jdk14-1.38.jar", index, package=lambda: "org.bouncycastle.crypto")
    assert (hit["coordinate"], hit["named_by"], hit["alternatives"]) == (
        ("org.bouncycastle", "bcprov-jdk14", "1.38"), "file name", [OLD_BOUNCY])
    # 1.38 is not a version of the 124-140 line, nor of the xfire one.
    alone = OneCoordinateIndex({BOUNCY: OLD_BOUNCY}, {k: v for k, v in BOUNCY_LINES.items() if k[0] != "org.bouncycastle"})
    assert maven.lookup_hash(net, BOUNCY, "bcprov-jdk14-1.38.jar", alone)["coordinate"] == OLD_BOUNCY
    # The file's own name for the indexed coordinate settles it.
    assert maven.lookup_hash(net, BOUNCY, "bcprov-jdk14-138.jar", index)["coordinate"] == OLD_BOUNCY
    # A name unrelated to the indexed artifact proves nothing, even one the index knows without that version.
    renamed = OneCoordinateIndex({BOUNCY: OLD_BOUNCY}, {**BOUNCY_LINES, ("org.example", "crypto"): ["1.37", "1.39"]})
    assert maven.lookup_hash(net, BOUNCY, "crypto-1.38.jar", renamed)["coordinate"] == OLD_BOUNCY
    # The longest artifactId the name can be read as comes first: log4j-1.2-api 2.17.1, not log4j 1.2-api-2.17.1.
    bridge, repackaged = "c7" * 20, ("org.example.repack", "log4j-1.2-api", "r5")
    lines = OneCoordinateIndex({bridge: repackaged}, {
        repackaged[:2]: ["r4", "r5"], ("org.apache.logging.log4j", "log4j-1.2-api"): ["2.17.0", "2.17.2"],
        ("log4j", "log4j"): ["1.1", "1.2.17"]})
    assert maven.lookup_hash(net, bridge, "log4j-1.2-api-2.17.1.jar", lines)["coordinate"] == (
        "org.apache.logging.log4j", "log4j-1.2-api", "2.17.1")
    # A version the line has a file for is another file.
    taken = OneCoordinateIndex({BOUNCY: OLD_BOUNCY}, {**BOUNCY_LINES, ("org.bouncycastle", "bcprov-jdk14"): ["1.38"]})
    assert maven.lookup_hash(net, BOUNCY, "bcprov-jdk14-1.38.jar", taken)["coordinate"] == OLD_BOUNCY
    assert net.offline_misses == 0


def test_the_groupid_a_file_name_is_given_is_the_package_s_then_the_indexed_one_then_the_longest_line(tmp_path):
    net = quiet_net(tmp_path, offline=True)
    servlet, mirror = "d4" * 20, ("org.example.dependencies.servlet", "servlet-api-2.5", "2.0")
    index = OneCoordinateIndex({servlet: mirror}, {
        mirror[:2]: ["2.0"], ("javax.servlet", "servlet-api"): ["3.0-alpha-1"],
        ("servletapi", "servlet-api"): ["2.2", "2.3", "2.4"], ("tomcat", "servlet-api"): ["5.5.12", "5.5.23"]})
    assert maven.lookup_hash(net, servlet, "servlet-api-2.5.jar", index, package=lambda: "javax.servlet.http")[
        "coordinate"] == ("javax.servlet", "servlet-api", "2.5")
    assert maven.lookup_hash(net, servlet, "servlet-api-2.5.jar", index)["coordinate"] == (
        "servletapi", "servlet-api", "2.5")
    annotations, older = "e5" * 20, ("com.google.code.findbugs", "jsr305", "2.0.3")
    index = OneCoordinateIndex({annotations: older}, {
        older[:2]: ["1.3.9", "2.0.3", "3.0.1", "3.0.2"],
        ("dev.example.jpms", "jsr305"): ["3.0.2-r1", "3.0.2-r2", "3.0.2-r4", "3.0.2-r5", "3.0.2-r6"]})
    assert maven.lookup_hash(net, annotations, "jsr305-3.0.0.jar", index, package=lambda: "javax.annotation")[
        "coordinate"] == ("com.google.code.findbugs", "jsr305", "3.0.0")
    # With no line around the version, the indexed groupId, which publishes this very file, before a longer line.
    last = OneCoordinateIndex(index.entries, {**index.versions, older[:2]: ["1.3.9", "2.0.3"]})
    assert maven.lookup_hash(net, annotations, "jsr305-3.0.0.jar", last)["coordinate"] == (
        "com.google.code.findbugs", "jsr305", "3.0.0")
    # Before the indexed groupId: the line whose releases come before and after the version.
    first = ("net.example.findbugs", "jsr305", "1.3.7")
    index = OneCoordinateIndex({annotations: first}, {
        first[:2]: ["1.3.2", "1.3.7"], older[:2]: ["1.3.9", "2.0.3", "3.0.1", "3.0.2"]})
    assert maven.lookup_hash(net, annotations, "jsr305-2.0.2.jar", index)["coordinate"] == (
        "com.google.code.findbugs", "jsr305", "2.0.2")
    # Of groupIds neither the package nor the index points to, the one that published the artifact longest.
    widget, carrier = "a8" * 20, ("org.example.bundle", "widget-2.5", "1")
    index = OneCoordinateIndex({widget: carrier}, {
        carrier[:2]: ["1"], ("aa", "widget"): ["1.0"], ("bb", "widget"): ["1.0", "2.0", "2.4"]})
    assert maven.lookup_hash(net, widget, "widget-2.5.jar", index)["coordinate"] == ("bb", "widget", "2.5")
    el, bundled = "f6" * 20, ("tomcat", "commons-el", "5.5.23")
    index = OneCoordinateIndex({el: bundled}, {bundled[:2]: ["5.5.23"], ("commons-el", "commons-el"): []})
    assert maven.lookup_hash(net, el, "commons-el-1.0.jar", index)["coordinate"] == ("commons-el", "commons-el", "1.0")


class SeveralCoordinateIndex(OneCoordinateIndex):
    """An index whose later additions file the same file under a second coordinate."""

    def coordinates_for_sha1(self, sha1):
        return list(self.entries.get(sha1, []))


def test_of_indexed_coordinates_that_fit_alike_the_line_that_went_on_publishing_names_the_file(tmp_path):
    shared, early, late = "b9" * 20, ("org.alpha", "lib", "1.0"), ("org.beta", "lib", "1.0")
    for listed in ([early, late], [late, early]):
        index = SeveralCoordinateIndex({shared: listed}, {early[:2]: ["1.0"], late[:2]: ["0.9", "1.0", "1.1", "2.0"]})
        hit = maven.lookup_hash(quiet_net(tmp_path, offline=True), shared, "lib-1.0.jar", index)
        assert (hit["coordinate"], hit["alternatives"]) == (late, [early])


def test_without_the_index_the_same_listing_in_any_order_gives_the_same_coordinates(tmp_path):
    listed = [NETBEANS, ("org.lucee", "commons-io", "2.6.0"), COMMONS_IO]
    for order, expected in ((listed, COMMONS_IO), (listed[::-1], COMMONS_IO)):
        net = Net(cache_dir=tmp_path / str(len(order)) / str(order[0]), sleep=lambda s: None,
                  transport=ScriptedTransport({"api.deps.dev": deps_dev_answer(*order)}))
        hit = maven.lookup_hash(net, REPUBLISHED, "io.jar")
        assert (hit["coordinate"], hit["licenses"], sorted(hit["alternatives"])) == (
            expected, ["Apache-2.0"], sorted(listed[:2]))
    moved = [OLD_BOUNCY, ("org.bouncycastle", "bcprov-jdk14", "1.38")]
    for order in (moved, moved[::-1]):
        net = Net(cache_dir=tmp_path / "bc" / order[0][0], sleep=lambda s: None,
                  transport=ScriptedTransport({"api.deps.dev": deps_dev_answer(*order)}))
        assert maven.lookup_hash(net, BOUNCY, "bc.jar", package=lambda: "org.bouncycastle.crypto")[
            "coordinate"] == moved[1]
        assert maven.lookup_hash(net, BOUNCY, "bc.jar")["coordinate"] == OLD_BOUNCY


def test_without_the_index_the_groupid_the_packages_are_in_then_the_alphabet_decide(tmp_path):
    # A longer groupId is a moved project as often as a republication: Oracle's is the longer one.
    oracle = [("com.oracle.ojdbc", "ojdbc8", "19.3.0.0"), ("com.oracle.database.jdbc", "ojdbc8", "19.3.0.0")]
    # Sharing org.example with the package is not being its groupId.
    bundled = [("org.example.bundles", "widget", "1.0"), ("org.example.widget", "widget", "1.0")]
    cases = ((oracle, "ojdbc8-19.3.0.0.jar", "oracle.jdbc", oracle[1]),
             (bundled, "widget-1.0.jar", "org.example.widget.core", bundled[1]),
             (bundled, "widget-1.0.jar", "org.example.other", bundled[0]))
    for number, (listed, filename, package, expected) in enumerate(cases):
        for order in (listed, listed[::-1]):
            net = Net(cache_dir=tmp_path / str(number) / order[0][0], sleep=lambda s: None,
                      transport=ScriptedTransport({"api.deps.dev": deps_dev_answer(*order)}))
            assert maven.lookup_hash(net, REPUBLISHED, filename, package=lambda: package)["coordinate"] == expected
