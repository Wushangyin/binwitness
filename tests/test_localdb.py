"""Local datasets: syncing (full, incremental, resumed), OSV range evaluation, and scans that use them."""
import base64
import gzip
import hashlib
import io
import json
import sqlite3
import struct
import tarfile
import time
import urllib.parse
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from binwitness import localdb, maven
from binwitness.cli import main
from binwitness.localdb import Fetcher, LocalDb, expand
from binwitness.net import Net
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
        start = int(headers["Range"][len("bytes="):-1]) if "Range" in headers else 0
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
    """The local index as Trivy builds it: each file under a single coordinate."""

    def __init__(self, entries):
        self.entries = entries

    def has(self, name):
        return name == "maven-hashes"

    def coordinates_for_sha1(self, sha1):
        return [self.entries[sha1]] if sha1 in self.entries else []


def deps_dev_answer(*coordinates):
    return {"results": [{"version": {"versionKey": {"system": "MAVEN", "name": f"{g}:{a}", "version": v},
                                     "licenses": ["Apache-2.0"]}} for g, a, v in coordinates]}


REPUBLISHED = "81" * 20
INDEX = OneCoordinateIndex({REPUBLISHED: ("org.netbeans.external", "org-apache-commons-io", "RELEASE113")})


def test_index_coordinate_that_does_not_name_the_file_defers_to_the_registry(tmp_path):
    transport = ScriptedTransport({"api.deps.dev": deps_dev_answer(
        ("commons-io", "commons-io", "2.6"), ("org.netbeans.external", "org-apache-commons-io", "RELEASE113"))})
    net = Net(cache_dir=tmp_path / "cache", transport=transport, sleep=lambda s: None)
    hit = maven.lookup_hash(net, REPUBLISHED, "commons-io-2.6.jar", INDEX)
    assert (hit["coordinate"], hit["source"]) == (("commons-io", "commons-io", "2.6"), "deps.dev")
    assert hit["alternatives"] == [("org.netbeans.external", "org-apache-commons-io", "RELEASE113")]
    # A renamed file gets the coordinate a scan without the index would give it.
    assert maven.lookup_hash(net, REPUBLISHED, "io.jar", INDEX)["coordinate"] == \
        maven.lookup_hash(net, REPUBLISHED, "io.jar")["coordinate"]
    # Offline, the cached answer decides the same way.
    offline = Net(cache_dir=tmp_path / "cache", offline=True, transport=ScriptedTransport({"": never}))
    assert maven.lookup_hash(offline, REPUBLISHED, "commons-io-2.6.jar", INDEX)["coordinate"] == (
        "commons-io", "commons-io", "2.6")


def test_index_coordinate_that_names_the_file_needs_no_request(tmp_path):
    net = Net(cache_dir=tmp_path / "cache", transport=ScriptedTransport({"": never}), sleep=lambda s: None)
    hit = maven.lookup_hash(net, REPUBLISHED, "org-apache-commons-io-RELEASE113.jar", INDEX)
    assert (hit["coordinate"], hit["source"]) == (
        ("org.netbeans.external", "org-apache-commons-io", "RELEASE113"), "Maven Central index, local copy")


def test_offline_without_the_registry_answer_keeps_the_index_coordinate(tmp_path):
    net = Net(cache_dir=tmp_path / "cache", offline=True, transport=ScriptedTransport({"": never}))
    hit = maven.lookup_hash(net, REPUBLISHED, "commons-io-2.6.jar", INDEX)
    assert hit["coordinate"] == ("org.netbeans.external", "org-apache-commons-io", "RELEASE113")
    assert net.offline_misses == 1


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
    index = OneCoordinateIndex({shared: ("org.example.mirror", "json-lib", "2.4")})
    assert maven.lookup_hash(net, shared, "json-lib-2.4-jdk15.jar", index, original)["coordinate"] == original
    agreeing = OneCoordinateIndex({shared: original})
    quiet = Net(cache_dir=tmp_path / "other", transport=ScriptedTransport({"": never}), sleep=lambda s: None)
    assert maven.lookup_hash(quiet, shared, "json-lib-2.4-jdk15.jar", agreeing, original)["coordinate"] == original
