"""Local copies of public datasets, so a scan can identify jars and match advisories without the network.

How much to keep locally is a per-machine choice:

* nothing: every lookup goes to the online services and each answer is cached as it arrives, so only what
  scans actually needed is stored (``~/.cache/binwitness``);
* some datasets: ``binwitness db sync osv-maven kev``;
* everything: ``binwitness db sync all``.

``binwitness db sync`` with no names brings the installed datasets up to date. OSV lists every record by
modification time, so an update fetches only the records changed since the previous one. The CISA
catalog is small and fetched whole. The Maven Central hash index is published as a single file and is
downloaded again only when its digest changes. NVD publishes a feed per year and one of the last eight days'
changes; a copy synced within a week is updated from the latter, an older one is downloaded again. The CVE
Program publishes its list as a snapshot every midnight and the changes since every hour and at the end of each
day; a copy is brought up to date from the changes of the days it lacks, and downloaded again past six weeks.
"""
from __future__ import annotations

import glob
import gzip
import hashlib
import http.client
import io
import json
import os
import posixpath
import re
import shutil
import sqlite3
import struct
import tarfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
    import msvcrt

from binwitness import cna, fixes, nvd
from binwitness.net import RETRY_STATUSES, USER_AGENT, default_cache_dir, map_parallel, open_url
from binwitness.vulns import KEV, OSV_ECOSYSTEM

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
GHCR = "https://ghcr.io"
JAVA_DB = "aquasecurity/trivy-java-db"
JAVA_DB_TAG = "1"
JAVA_DB_LAYER = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CENTRAL_INDEX = "https://repo1.maven.org/maven2/.index"
INDEX_PROPERTIES = f"{CENTRAL_INDEX}/nexus-maven-repository-index.properties"
RECENT_FILE = "maven-hashes-recent.sqlite"
# Beyond this many changed records, downloading the whole archive again is quicker than fetching each one.
INCREMENTAL_LIMIT = 5000
# Records deleted from OSV outright (rare; withdrawal is the usual way) never appear in the change list, so
# an incrementally updated copy is rebuilt from the archive once a month to drop them.
REBUILD_DAYS = 30
STALE_DAYS = 7
# Trivy rebuilds its hash index every day as one 1 GB file, with no incremental form. Maven Central publishes
# the additions to its own index every week or two as a chunk of 10-50 MB and lists several months of them;
# those keep the copy current, and the base is downloaded again only this rarely.
HASHES_REFRESH_DAYS = 180
# Chunks are cut every week or two and the base daily: also apply the week before the base, so that nothing
# published around the day it was built falls between the two.
CHUNK_OVERLAP = 7 * 86400
# Central limits index downloads per address and asks clients not to look more often than the index changes.
CENTRAL_CHECK_DAYS = 7
CSV_CHUNK = 64 * 1024
# NVD's modified feed holds the changes of the last eight days; a day is kept spare.
NVD_MODIFIED_DAYS = 7
# NVD serves a connection at a small part of a line's speed (about 100 kB/s seen, as much again for each further
# connection): a full download fetches its yearly feeds a few at a time.
NVD_WORKERS = 4
# GitHub serves a commit's diff to anyone, within limits per address: a few at a time, and stop when it refuses.
FIX_WORKERS = 4
FIX_BATCH = 40
# One connection can be held far below what the line gives: the same file, an hour apart, at 140 kB/s and at 2.7 MB/s;
# of four at once, three fetched their 4 MB in seconds and one in minutes. A large file is fetched in pieces of
# PART_SIZE over so many connections at once, so that a slow one holds up a piece, not the file.
DOWNLOAD_CONNECTIONS = 4
PART_SIZE = 8 << 20
FIX_FAILURES_TO_STOP = 8
# cvelistV5 keeps each day's changes as a release for at least seven weeks (seen in October 2026); a copy further
# behind is downloaded again.
CVELIST_DELTA_DAYS = 40
# Records stored without their text (see _cvelist_finish) whose text is needed since, fetched one by one: at most
# this many per sync, a few at a time.
CVELIST_FETCH_LIMIT = 1000
CVELIST_WORKERS = 4
CVELIST_FAILURES_TO_STOP = 8
CVELIST_SCHEMA = """
CREATE TABLE records(id TEXT PRIMARY KEY, cna TEXT, published TEXT, updated TEXT, body BLOB);
CREATE TABLE keys(key TEXT, id TEXT, PRIMARY KEY (key, id)) WITHOUT ROWID;
CREATE TABLE packages(name TEXT, module TEXT, id TEXT, how TEXT);
CREATE TABLE cpes(vendor TEXT, product TEXT, id TEXT);
CREATE TABLE links(key TEXT, name TEXT, cves INTEGER);
"""
CVELIST_INDEXES = ["CREATE INDEX keys_id ON keys(id)",
                   "CREATE INDEX packages_module ON packages(module)", "CREATE INDEX packages_id ON packages(id)",
                   "CREATE INDEX cpes_product ON cpes(vendor, product)", "CREATE INDEX cpes_id ON cpes(id)",
                   "CREATE INDEX links_name ON links(name)"]
CVE_FILE = re.compile(r"(?:^|/)CVE-\d{4}-\d{4,}\.json$")
# The data behind spring.io/security: every advisory of the Spring projects, in one file.
SPRING_ADVISORIES = "https://spring.io/page-data/security/page-data.json"
MONTHS = {month: number for number, month in enumerate(
    ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
     "December"], 1)}
# Rows per SQL statement when looking up a list of ids: SQLite allows a few hundred parameters at most.
ID_BATCH = 500
# Rows read at a time when going through all of a table: their texts are not all held at once.
RECORD_PAGE = 1000


@dataclass(frozen=True)
class Dataset:
    description: str
    size: str
    file: str


DATASETS = {
    "osv-maven": Dataset("OSV advisories for Maven packages", "10 MB download", "osv-maven.sqlite"),
    "osv-npm": Dataset("OSV advisories for npm packages, malicious-package reports included", "210 MB download",
                       "osv-npm.sqlite"),
    "kev": Dataset("CISA Known Exploited Vulnerabilities catalog", "2 MB download", "kev.json"),
    "maven-hashes": Dataset("SHA-1 of every jar on Maven Central (Trivy java-db, then Central's weekly additions)",
                            "1 GB download, then 10-50 MB every week or two", "maven-hashes.db"),
    "nvd": Dataset("NVD CVE records that name an application (CPE), for candidates",
                   "235 MB download, then 15 MB a day", "nvd.sqlite"),
    "spring": Dataset("Spring security advisories (spring.io), for the modules and versions each names, for "
                      "candidates", "260 kB download, 140 kB on disk", "spring.json"),
    # After osv-maven: what it keeps and learns follows the CVEs OSV attributes.
    "cvelist": Dataset("CVE records as their CNAs published them (cvelistV5), for candidates NVD has not given a "
                       "CPE yet", "650 MB download, then about 5 MB a day", "cvelist.sqlite"),
    # Last: it is read from the NVD and CNA records of the packages OSV knows.
    "fixes": Dataset("Files changed by the GitHub commits CVE records or vendor pages cite as the fix, for "
                     "candidates", "about 430 commits from github.com, 8 MB download; then those of new records",
                     "fixes.json"),
}
GROUPS = {"vulns": ("osv-maven", "osv-npm", "kev"), "java": ("osv-maven", "kev", "maven-hashes"),
          "all": tuple(DATASETS)}
OSV_DATASET = {"maven": "osv-maven", "npm": "osv-npm"}
OSV_FOLDER = {"osv-maven": OSV_ECOSYSTEM["maven"], "osv-npm": OSV_ECOSYSTEM["npm"]}
ECOSYSTEM_OF = {dataset: ecosystem for ecosystem, dataset in OSV_DATASET.items()}
SCHEMA = """
CREATE TABLE records(id TEXT PRIMARY KEY, modified TEXT, withdrawn INTEGER, body BLOB);
CREATE TABLE affected(name TEXT, id TEXT);
CREATE TABLE cves(cve TEXT, id TEXT);
"""


class SyncError(Exception):
    """A dataset could not be brought up to date. The copy already installed is left as it was."""


class HttpStatusError(SyncError):
    def __init__(self, url: str, status: int):
        super().__init__(f"{url}: HTTP {status}")
        self.status = status


def _refuse_if_limited(url: str, status: int, headers: dict):
    """Stop at the first rate-limit answer: Maven Central extends a block for every request made during it."""
    if status != 429:
        return
    wait = _header(headers, "Retry-After")
    later = f"; try again in {int(wait) / 3600:.1f} hours" if wait and wait.isdigit() else "; try again later"
    raise SyncError(f"{url}: the server is limiting downloads from this address{later}")


def default_db_dir() -> Path:
    if os.environ.get("BINWITNESS_DB"):
        return Path(os.environ["BINWITNESS_DB"])
    # Not "db": the response cache shards its files into two-hex-digit directories, and "db" is one of them.
    return default_cache_dir() / "datasets"


def expand(names: list[str]) -> list[str]:
    """Dataset names, with group names replaced by their members, in a stable order."""
    unknown = [n for n in names if n not in DATASETS and n not in GROUPS]
    if unknown:
        raise ValueError(f"unknown dataset {', '.join(unknown)}; choose from {', '.join([*DATASETS, *GROUPS])}")
    chosen = {d for n in names for d in GROUPS.get(n, (n,))}
    return [n for n in DATASETS if n in chosen]


# ---- downloads ------------------------------------------------------------------------------------------

Opener = Callable[[str, dict], tuple[int, dict, object]]


def urllib_opener(url: str, headers: dict):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    try:
        response = open_url(request)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers or {}), error
    return response.status, dict(response.headers), response


def _header(headers: dict, name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), None)


@dataclass
class Fetcher:
    opener: Opener = urllib_opener
    retries: int = 5
    sleep: Callable[[float], None] = time.sleep

    def read(self, url: str, headers: dict | None = None) -> tuple[int, bytes]:
        def attempt():
            status, answer, stream = self.opener(url, headers or {})
            with closing(stream):
                _refuse_if_limited(url, status, answer)
                return status, stream.read()
        return self._retry(url, attempt)

    def download(self, url: str, target: Path, headers: dict | Callable[[], dict] | None = None,
                 sha256: str | None = None, progress: Callable[[int, int | None], None] | None = None,
                 connections: int = 1):
        """Stream ``url`` into ``target``. A connection that drops resumes where it stopped; ``If-Range``
        makes the server send the whole file instead if it changed in the meantime. ``headers`` may be a
        function, called before every attempt, for credentials that expire during a long download.
        ``connections``: a file the server sends by ranges is fetched in pieces over so many at once."""
        if connections > 1 and not target.exists() and self._download_parts(url, target, headers, progress,
                                                                              connections):
            self._check_digest(url, target, sha256)
            return
        validator = {}

        def size():
            return target.stat().st_size if target.exists() else 0

        def attempt():
            have = size()
            sent = dict((headers() if callable(headers) else headers) or {})
            if have:
                sent["Range"] = f"bytes={have}-"
                if validator.get("etag"):
                    sent["If-Range"] = validator["etag"]
            status, answer, stream = self.opener(url, sent)
            with closing(stream):
                _refuse_if_limited(url, status, answer)
                if status == 416 and have:
                    return 200, None
                if status not in (200, 206):
                    return status, None
                validator.setdefault("etag", _header(answer, "ETag"))
                done = have if status == 206 else 0
                total = _total_size(answer, status, done)
                with target.open("ab" if status == 206 else "wb") as out:
                    while chunk := stream.read(1 << 20):
                        out.write(chunk)
                        done += len(chunk)
                        if progress:
                            progress(done, total)
            # http.client reports a connection closed early as a normal end of data.
            if total is not None and done < total:
                raise ConnectionError(f"connection closed after {done} of {total} bytes")
            return 200, None

        reached = [size()]

        def progressed():
            now = size()
            moved, reached[0] = now > reached[0], now
            return moved

        status, _ = self._retry(url, attempt, progressed)
        if status != 200:
            raise HttpStatusError(url, status)
        self._check_digest(url, target, sha256)

    @staticmethod
    def _check_digest(url: str, target: Path, sha256: str | None):
        if sha256:
            algorithm, _, expected = sha256.partition(":")
            digest = hashlib.sha256()
            with target.open("rb") as stream:
                while chunk := stream.read(1 << 20):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                target.unlink()
                raise SyncError(f"{url}: downloaded file does not match its {algorithm} digest")

    def _download_parts(self, url, target: Path, headers, progress, connections: int) -> bool:
        """Fetch ``url`` in pieces over several connections, each piece resuming where it stopped, also in a
        later sync; join them into ``target``. False, having fetched nothing, when the server does not send
        ranges or the file is no larger than a piece; and when the file changed under pieces fetched before."""
        def sent():
            return dict((headers() if callable(headers) else headers) or {})

        def probe():
            status, answer, stream = self.opener(url, {**sent(), "Range": "bytes=0-0"})
            with closing(stream):
                _refuse_if_limited(url, status, answer)
                if status != 206:
                    return status, None
                return status, (_total_size(answer, status, 0),
                                _header(answer, "ETag") or _header(answer, "Last-Modified"))
        status, found = self._retry(url, probe)
        if status not in (200, 206, 416):
            raise HttpStatusError(url, status)
        if found is None or found[0] is None:
            return False
        total, etag = found
        count = -(-total // PART_SIZE)
        if count < 2:
            return False
        layout = {"total": total, "etag": etag, "piece": PART_SIZE}
        plan = target.with_name(target.name + ".parts")
        pieces = [target.with_name(f"{target.name}.{k + 1}-of-{count}") for k in range(count)]
        try:
            resumed = json.loads(plan.read_text("utf-8")) == layout
        except (OSError, ValueError):
            resumed = False
        if not resumed:
            for stale in target.parent.glob(f"{glob.escape(target.name)}.*-of-*"):
                stale.unlink()
            plan.write_text(json.dumps(layout), "utf-8")
        bounds = [(k * PART_SIZE, min(total, (k + 1) * PART_SIZE) - 1) for k in range(count)]
        lock = threading.Lock()
        stopped = threading.Event()

        def size(path):
            return path.stat().st_size if path.exists() else 0
        done = [size(piece) for piece in pieces]

        def fetch(k):
            start, end = bounds[k]
            piece, wanted = pieces[k], end - start + 1

            def attempt():
                have = size(piece)
                if have >= wanted:
                    return 206, None
                asked = {**sent(), "Range": f"bytes={start + have}-{end}"}
                if etag:
                    asked["If-Range"] = etag
                status, answer, stream = self.opener(url, asked)
                with closing(stream):
                    _refuse_if_limited(url, status, answer)
                    if status != 206:
                        # 200: the whole file, as it is now; it changed since the other pieces were fetched.
                        return status, None
                    with piece.open("ab") as out:
                        while have < wanted and (chunk := stream.read(min(1 << 20, wanted - have))):
                            out.write(chunk)
                            have += len(chunk)
                            with lock:
                                done[k] = have
                                if progress:
                                    progress(sum(done), total)
                if have < wanted:
                    raise ConnectionError(f"connection closed after {have} of {wanted} bytes of piece {k + 1}")
                return 206, None
            reached = [size(piece)]

            def progressed():
                now = size(piece)
                moved, reached[0] = now > reached[0], now
                return moved
            # A piece that fails or finds the file changed starts no more; those under way finish, and are kept
            # for the next sync.
            if stopped.is_set():
                return None
            try:
                status = self._retry(url, attempt, progressed)[0]
            except SyncError as error:
                status = error
            if status != 206:
                stopped.set()
            return status
        statuses = map_parallel(fetch, range(count), min(connections, count))
        if 200 in statuses:
            for piece in pieces:
                piece.unlink(missing_ok=True)
            plan.unlink(missing_ok=True)
            return False
        failed = next((s for s in statuses if s not in (206, None)), None)
        if isinstance(failed, SyncError):
            raise failed
        if failed is not None:
            raise HttpStatusError(url, failed)
        joining = target.with_name(target.name + ".joining")
        with joining.open("wb") as out:
            for piece in pieces:
                with piece.open("rb") as stream:
                    shutil.copyfileobj(stream, out, 1 << 20)
        os.replace(joining, target)
        for piece in pieces:
            piece.unlink()
        plan.unlink()
        return True

    def _retry(self, url, attempt, progressed: Callable[[], bool] = lambda: False):
        failures, last = 0, None
        while failures < self.retries:
            try:
                status, body = attempt()
            except (OSError, http.client.HTTPException) as error:
                last = repr(error)
            else:
                if status not in RETRY_STATUSES:
                    return status, body
                last = f"HTTP {status}"
            # A slow line can drop a large download many times; each drop that got further is not a failure.
            if progressed():
                failures = 0
                continue
            failures += 1
            if failures < self.retries:
                self.sleep(2 ** failures)
        raise SyncError(f"{url}: {last} after {self.retries} attempts")


def _total_size(headers: dict, status: int, offset: int) -> int | None:
    span = _header(headers, "Content-Range") if status == 206 else None
    if span and "/" in span and span.rsplit("/", 1)[1].isdigit():
        return int(span.rsplit("/", 1)[1])
    length = _header(headers, "Content-Length")
    return offset + int(length) if length and length.isdigit() else None


def _stamp(text: str) -> str:
    """OSV times as sortable text. Their fractions run from none to nine digits ("...10.96726706Z")."""
    head, _, fraction = text.strip().rstrip("Z").partition(".")
    return f"{head}.{fraction[:9]:0<9}" if head else ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---- the local store ------------------------------------------------------------------------------------

class LocalDb:
    def __init__(self, directory: Path | None = None):
        self.directory = Path(directory or default_db_dir())
        self._lock = threading.Lock()
        self._connections: dict[str, sqlite3.Connection] = {}
        self._kev: dict[str, str] | None = None
        self._advisories: dict[str, dict] | None = None
        self._advised: dict[str, list[str]] | None = None
        self._fixes: dict | None = None
        self._known: dict[str, bool] = {}
        self.used: set[str] = set()
        self.state = self._read_state()

    @classmethod
    def open(cls, directory: Path | None = None) -> LocalDb | None:
        """The store, or None when no dataset is installed (scans then behave exactly as without one)."""
        db = cls(directory)
        return db if db.installed() else None

    def path(self, name: str) -> Path:
        return self.directory / DATASETS[name].file

    def has(self, name: str) -> bool:
        return name in self.state and self.path(name).exists()

    def installed(self) -> list[str]:
        return [n for n in DATASETS if self.has(n)]

    # ---- lookups --------------------------------------------------------------------------------------

    def _rows(self, name: str, sql: str, parameters: tuple, path: Path | None = None) -> list:
        path = path or self.path(name)
        with self._lock:
            connection = self._connections.get(str(path))
            if connection is None:
                connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False)
                self._connections[str(path)] = connection
            self.used.add(name)
            return connection.execute(sql, parameters).fetchall()

    def _recent(self) -> Path | None:
        path = self.directory / RECENT_FILE
        return path if path.exists() else None

    def coordinates_for_sha1(self, sha1: str) -> list[tuple[str, str, str]]:
        key = bytes.fromhex(sha1)
        rows = self._rows("maven-hashes", "SELECT a.group_id, a.artifact_id, i.version FROM indices i "
                          "JOIN artifacts a ON a.id = i.artifact_id WHERE i.sha1 = ?", (key,))
        if self._recent():
            rows += self._rows("maven-hashes", "SELECT group_id, artifact_id, version FROM hashes WHERE sha1 = ?",
                               (key,), self._recent())
        return list(dict.fromkeys(tuple(r) for r in rows))

    def osv_records(self, ecosystem: str, name: str) -> list[dict]:
        rows = self._rows(OSV_DATASET[ecosystem], "SELECT r.body FROM affected a JOIN records r ON r.id = a.id "
                          "WHERE a.name = ? AND r.withdrawn = 0 ORDER BY r.id", (name,))
        return [json.loads(zlib.decompress(body)) for (body,) in rows]

    def cve_index_missing(self, name: str | None) -> str | None:
        """Why candidates cannot be looked for with this OSV dataset, if they cannot."""
        if not name or not self.has(name):
            return f"the local {name or 'OSV'} dataset is not installed (binwitness db sync {name or 'vulns'})"
        if not self._rows(name, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'cves'", ()):
            return f"the local {name} dataset predates the CVE index candidates need (binwitness db sync {name})"
        return None

    def osv_cves(self, ecosystem: str, name: str) -> set[str]:
        """CVE ids of the advisories OSV attributes to a package, withdrawn ones left out."""
        return {c for (c,) in self._rows(OSV_DATASET[ecosystem], "SELECT DISTINCT c.cve FROM affected a "
                                         "JOIN records r ON r.id = a.id JOIN cves c ON c.id = a.id "
                                         "WHERE a.name = ? AND r.withdrawn = 0", (name,))}

    def osv_project_cves(self, ecosystem: str, key: str) -> set[str]:
        """Same as :meth:`osv_cves`, for every package of a project (see :func:`binwitness.nvd.project`)."""
        if key[-1:] in (":", "/"):
            # A range, not LIKE: LIKE ignores the index on names.
            where, parameters = "a.name >= ? AND a.name < ?", (key, key[:-1] + chr(ord(key[-1]) + 1))
        else:
            where, parameters = "a.name = ?", (key,)
        return {c for (c,) in self._rows(OSV_DATASET[ecosystem], "SELECT DISTINCT c.cve FROM affected a "
                                         "JOIN records r ON r.id = a.id JOIN cves c ON c.id = a.id "
                                         f"WHERE {where} AND r.withdrawn = 0", parameters)}

    def osv_names(self, ecosystem: str, prefix: str) -> list[str]:
        """Names of the packages OSV has advisories for that begin with a prefix, withdrawn ones included."""
        return [n for (n,) in self._rows(OSV_DATASET[ecosystem], "SELECT DISTINCT name FROM affected "
                                         "WHERE name >= ? AND name < ? ORDER BY name",
                                         (prefix, prefix[:-1] + chr(ord(prefix[-1]) + 1)))]

    def maven_groups(self, artifact: str) -> list[str]:
        """The groupIds that publish an artifactId, as far as the hash index knows; none when it is not installed."""
        if not self.has("maven-hashes"):
            return []
        rows = self._rows("maven-hashes", "SELECT group_id FROM artifacts WHERE artifact_id = ?", (artifact,))
        if self._recent():
            rows += self._rows("maven-hashes", "SELECT DISTINCT group_id FROM hashes WHERE artifact_id = ?",
                               (artifact,), self._recent())
        return sorted({g for (g,) in rows})

    def osv_attribution(self, cves) -> dict[str, set[tuple[str, str]]]:
        """CVE id -> the packages (ecosystem, name) any installed OSV dataset attributes it to, withdrawn
        advisories included: a withdrawal is a judgement on that package, not a lead for another."""
        out: dict[str, set] = {}
        for name in self.installed():
            if name not in ECOSYSTEM_OF or self.cve_index_missing(name):
                continue
            for batch in _batches(sorted(set(cves))):
                for cve, package in self._rows(name, "SELECT c.cve, a.name FROM cves c JOIN affected a "
                                               f"ON a.id = c.id WHERE c.cve IN ({_marks(batch)})", tuple(batch)):
                    out.setdefault(cve, set()).add((ECOSYSTEM_OF[name], package))
        return out

    def nvd_ids(self, cpe: str) -> list[str]:
        vendor, _, product = cpe.partition(":")
        return [i for (i,) in self._rows("nvd", "SELECT DISTINCT id FROM cpes WHERE vendor = ? AND product = ? "
                                         "ORDER BY id", (vendor, product))]

    def nvd_cpes(self, cves) -> dict[str, set[str]]:
        """CVE id -> its CPEs (``vendor:product``), for the ids NVD gives any."""
        out: dict[str, set] = {}
        for batch in _batches(sorted(set(cves))):
            for ident, vendor, product in self._rows("nvd", "SELECT id, vendor, product FROM cpes "
                                                     f"WHERE id IN ({_marks(batch)})", tuple(batch)):
                out.setdefault(ident, set()).add(f"{vendor}:{product}")
        return out

    def nvd_record(self, ident: str) -> dict | None:
        rows = self._rows("nvd", "SELECT body FROM records WHERE id = ?", (ident,))
        return json.loads(zlib.decompress(rows[0][0])) if rows else None

    def nvd_without_cpe(self) -> dict[str, int]:
        """Records NVD has not given a CPE yet, by status: these cannot become candidates."""
        return dict(self._rows("nvd", "SELECT status, count(*) FROM unanalyzed GROUP BY status ORDER BY status", ()))

    def maven_versions(self, group: str, artifact: str) -> list[str]:
        """Versions of an artifact that have a jar in the hash index: as of the index, not of today."""
        rows = self._rows("maven-hashes", "SELECT DISTINCT i.version FROM indices i JOIN artifacts a "
                          "ON a.id = i.artifact_id WHERE a.artifact_id = ? AND a.group_id = ?", (artifact, group))
        if self._recent():
            rows += self._rows("maven-hashes", "SELECT DISTINCT version FROM hashes WHERE group_id = ? "
                               "AND artifact_id = ?", (group, artifact), self._recent())
        return list(dict.fromkeys(version for (version,) in rows))

    def data_as_of(self, name: str) -> str | None:
        return (self.state.get(name) or {}).get("data_as_of")

    def kev(self) -> dict[str, str]:
        with self._lock:
            if self._kev is None:
                data = json.loads(self.path("kev").read_text("utf-8"))
                self._kev = {v["cveID"]: v.get("dateAdded", "") for v in data.get("vulnerabilities", [])}
            self.used.add("kev")
            return self._kev

    def advisory_modules(self, cve: str) -> list[str] | None:
        """The modules (``groupId:artifactId``) the vendor's own advisory of a CVE names; None when no installed
        dataset has an advisory of it, an empty list when the advisory names none."""
        if not self.has("spring"):
            return None
        with self._lock:
            if self._advisories is None:
                self._advisories = json.loads(self.path("spring").read_text("utf-8"))["advisories"]
            self.used.add("spring")
        entry = self._advisories.get(cve)
        return list(entry["modules"]) if entry else None

    def advisory(self, cve: str) -> dict | None:
        """The vendor's own advisory of a CVE (modules, versions), as :func:`spring_advisories` stores it; a copy
        synced before versions were kept has none."""
        if self.advisory_modules(cve) is None:
            return None
        return {"versions": [], **self._advisories[cve]}

    def _advised_cves(self) -> list[str]:
        if not self.has("spring"):
            return []
        self.advisory_modules("")
        return sorted(c for c, entry in self._advisories.items() if entry["modules"])

    def advised(self, module: str) -> list[str]:
        """The CVEs whose advisory names a build of a module (see cna.module_key)."""
        if not self.has("spring"):
            return []
        self.advisory_modules("")
        with self._lock:
            if self._advised is None:
                by_module: dict[str, set[str]] = {}
                for cve, entry in self._advisories.items():
                    for name in entry["modules"]:
                        by_module.setdefault(cna.module_key(name), set()).add(cve)
                self._advised = {m: sorted(c) for m, c in by_module.items()}
        return self._advised.get(module, [])

    def cna_records(self, ids) -> dict[str, dict]:
        """CVE id -> its CNA record as :func:`binwitness.cna.trim` keeps it, for the ids stored with their text."""
        if not self.has("cvelist"):
            return {}
        out = {}
        for batch in _batches(sorted(set(ids))):
            for ident, body in self._rows("cvelist", f"SELECT id, body FROM records WHERE id IN ({_marks(batch)}) "
                                          "AND body IS NOT NULL", tuple(batch)):
                out[ident] = json.loads(zlib.decompress(body))
        return out

    def cna_meta(self, ids) -> dict[str, tuple[str, str, str]]:
        """CVE id -> (CNA short name, published, updated) for every published record of the ids."""
        if not self.has("cvelist"):
            return {}
        out = {}
        for batch in _batches(sorted(set(ids))):
            out.update((i, (c, p, u)) for i, c, p, u in self._rows(
                "cvelist", f"SELECT id, cna, published, updated FROM records WHERE id IN ({_marks(batch)})",
                tuple(batch)))
        return out

    def cna_packages(self, module: str) -> list[tuple[str, str, str]]:
        """(package, CVE id, how) of the CNA records that name a build of a module (see cna.module_key)."""
        return [tuple(r) for r in self._rows("cvelist", "SELECT name, id, how FROM packages WHERE module = ? "
                                             "ORDER BY id, name", (module,))]

    def cna_named_packages(self, ids) -> dict[str, list[tuple[str, str]]]:
        """CVE id -> the packages (name, how) its CNA record names."""
        out: dict[str, list] = {}
        for batch in _batches(sorted(set(ids))):
            for ident, name, how in self._rows("cvelist", "SELECT id, name, how FROM packages "
                                               f"WHERE id IN ({_marks(batch)}) ORDER BY name", tuple(batch)):
                out.setdefault(ident, []).append((name, how))
        return out

    def cna_cpe_ids(self, cpe: str) -> list[str]:
        vendor, _, product = cpe.partition(":")
        return [i for (i,) in self._rows("cvelist", "SELECT DISTINCT id FROM cpes WHERE vendor = ? AND product = ? "
                                         "ORDER BY id", (vendor, product))]

    def cna_links(self, name: str) -> dict[str, int]:
        """Product key -> the CVEs it was learned from, for the CNA product names learned for a package."""
        if not self.has("cvelist"):
            return {}
        return dict(self._rows("cvelist", "SELECT key, cves FROM links WHERE name = ? ORDER BY key", (name,)))

    def cna_key_ids(self, key: str) -> list[str]:
        return [i for (i,) in self._rows("cvelist", "SELECT DISTINCT id FROM keys WHERE key = ? ORDER BY id", (key,))]

    def known_package(self, name: str) -> bool:
        """Whether a Maven package exists as far as the datasets know: OSV has advisories for it, or the hash index
        has a jar of it."""
        if name not in self._known:
            group, _, artifact = name.partition(":")
            self._known[name] = bool(self.has("osv-maven") and self.osv_names("maven", name)[:1] == [name]) \
                or group in self.maven_groups(artifact)
        return self._known[name]

    def nvd_status(self, ids) -> dict[str, str]:
        """CVE id -> NVD's status, for the ids NVD holds: with a CPE or not yet given one."""
        out = {}
        for batch in _batches(sorted(set(ids))):
            marks = _marks(batch)
            out.update(self._rows("nvd", f"SELECT id, status FROM records WHERE id IN ({marks}) UNION ALL "
                                  f"SELECT id, status FROM unanalyzed WHERE id IN ({marks})", tuple(batch) * 2))
        return out

    def fix_of(self, cve: str) -> dict | None:
        """What the GitHub commits a record cites as its fix changed (see ``fixes.fix_of``); None when the dataset
        is not installed or the record cites no commit of its project."""
        if not self.has("fixes"):
            return None
        with self._lock:
            if self._fixes is None:
                self._fixes = json.loads(self.path("fixes").read_text("utf-8"))
            self.used.add("fixes")
        return fixes.fix_of(self._fixes["records"].get(cve), self._fixes["commits"])

    def provenance(self) -> dict:
        return {n: {"data_as_of": self.state[n].get("data_as_of"), "synced": self.state[n].get("synced")}
                for n in sorted(self.used)}

    def stale(self, now: float | None = None) -> list[str]:
        now = time.time() if now is None else now
        out = []
        for name in sorted(self.used):
            synced = datetime.fromisoformat(self.state[name]["synced"]).timestamp()
            days = (now - synced) / 86400
            if days > STALE_DAYS:
                out.append(f"local dataset {name} was last synced {days:.0f} days ago; run `binwitness db sync`")
        return out

    def close(self):
        with self._lock:
            for connection in self._connections.values():
                connection.close()
            self._connections.clear()

    # ---- maintenance ----------------------------------------------------------------------------------

    def status(self) -> list[dict]:
        rows = []
        for name, dataset in DATASETS.items():
            entry = self.state.get(name, {}) if self.has(name) else {}
            rows.append({"name": name, "description": dataset.description, "installed": bool(entry),
                         "data_as_of": entry.get("data_as_of"), "synced": entry.get("synced"),
                         "records": entry.get("records"),
                         "bytes": sum(f.stat().st_size for f in self._files(name) if f.exists()) if entry else None,
                         "download": dataset.size,
                         **({key: entry.get(key) for key in ("base_as_of", "chunk", "checked", "recent_records")}
                            if name == "maven-hashes" else {}),
                         **({"without_cpe": entry.get("without_cpe"),
                             "layout_current": entry.get("layout") == nvd.LAYOUT} if name == "nvd" else {}),
                         **({key: entry.get(key) for key in ("commits", "commits_not_read")}
                            if name == "fixes" else {}),
                         **({key: entry.get(key) for key in ("tag", "kept", "links", "bodies_not_fetched")}
                            if name == "cvelist" else {})})
        return rows

    def _files(self, name: str) -> list[Path]:
        return [self.path(name)] + ([self.directory / RECENT_FILE] if name == "maven-hashes" else [])

    def remove(self, names: list[str]):
        self.close()
        with self._exclusive():
            for name in names:
                for file in self._files(name):
                    file.unlink(missing_ok=True)
                self.state.pop(name, None)
            self._write_state()

    def sync(self, names: list[str], *, full: bool = False, hashes_every: float = HASHES_REFRESH_DAYS,
             fetcher: Fetcher | None = None,
             log: Callable[[str], None] = print, workers: int = 8) -> dict[str, str]:
        """Install or update each dataset; name -> outcome. A dataset that fails keeps its previous copy."""
        fetcher = fetcher or Fetcher()
        with self._exclusive():
            return self._sync(names, full, hashes_every, fetcher, log, workers)

    def _sync(self, names, full, hashes_every, fetcher, log, workers) -> dict[str, str]:
        outcomes = {}
        for name in names:
            try:
                if name in OSV_FOLDER:
                    entry, outcome = self._sync_osv(name, full, fetcher, log, workers)
                elif name == "kev":
                    entry, outcome = self._sync_kev(fetcher)
                elif name == "nvd":
                    entry, outcome = self._sync_nvd(full, fetcher, log)
                elif name == "spring":
                    entry, outcome = self._sync_spring(fetcher)
                elif name == "cvelist":
                    entry, outcome = self._sync_cvelist(full, fetcher, log)
                elif name == "fixes":
                    entry, outcome = self._sync_fixes(fetcher, log)
                else:
                    entry, outcome = self._sync_maven_hashes(full, hashes_every, fetcher, log)
            except (SyncError, OSError, ValueError, KeyError, sqlite3.Error, zipfile.BadZipFile,
                    tarfile.TarError, EOFError, zlib.error, struct.error) as error:
                outcomes[name] = f"failed: {error}"
                continue
            self.state[name] = {**self.state.get(name, {}), **entry, "synced": _now()}
            self._write_state()
            outcomes[name] = outcome
        # Which commits fixes reads follows the records of these: new ones may cite commits it has not read.
        moved = [n for n in ("osv-maven", "nvd", "cvelist")
                 if not outcomes.get(n, "up to date").startswith(("up to date", "failed"))]
        if moved and "fixes" not in outcomes and self.has("fixes"):
            unread = self._fixes_unread()
            if unread:
                outcomes["fixes"] = (f"not synced: {unread} commit{'' if unread == 1 else 's'} the records now cite "
                                     "not read yet (sync fixes)")
        # A failed download stays, so that the next sync resumes it instead of starting over.
        if not any(o.startswith("failed") for o in outcomes.values()):
            shutil.rmtree(self.directory / ".download", ignore_errors=True)
        return outcomes

    @contextmanager
    def _exclusive(self):
        """One sync or remove per directory at a time: two would write into the same partial download, and the
        one finishing last would write back a state file that lacks what the other installed."""
        self.directory.mkdir(parents=True, exist_ok=True)
        with open(self.directory / ".lock", "a+b") as handle:
            try:
                if fcntl:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise SyncError(f"another `binwitness db` command is working on {self.directory}; "
                                "run this one after it finishes") from None
            # Another process may have changed the state since this object read it.
            self.state = self._read_state()
            yield

    def _read_state(self) -> dict:
        try:
            return json.loads((self.directory / "state.json").read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def _write_state(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.directory / f"state.json.{os.getpid()}.tmp"
        temporary.write_text(json.dumps(self.state, indent=1, sort_keys=True), "utf-8")
        os.replace(temporary, self.directory / "state.json")

    def _scratch(self) -> Path:
        scratch = self.directory / ".download"
        scratch.mkdir(parents=True, exist_ok=True)
        return scratch

    def _progress(self, log, label):
        shown = [-1]

        def report(done, total):
            if total:
                tenth = done * 10 // total
                if tenth > shown[0]:
                    shown[0] = tenth
                    log(f"{label}: {done / 2**20:.0f} of {total / 2**20:.0f} MB")
        return report

    # ---- OSV ------------------------------------------------------------------------------------------

    def _sync_osv(self, name, full, fetcher, log, workers):
        entry = self.state.get(name, {}) if self.has(name) else {}
        rebuilt = entry.get("full_download")
        due = not rebuilt or time.time() - datetime.fromisoformat(rebuilt).timestamp() > REBUILD_DAYS * 86400
        if not full and not due:
            self._osv_cve_index(name, log)
            changes = self._osv_changes(name, fetcher, entry["data_as_of"])
            if changes is not None:
                return self._osv_apply(name, changes, entry, fetcher, workers)
            log(f"{name}: more than {INCREMENTAL_LIMIT} records changed; downloading the archive instead")
        newest, count = self._osv_rebuild(name, fetcher, log)
        return ({"data_as_of": newest, "records": count, "full_download": _now()},
                f"downloaded {count} records")

    def _osv_rebuild(self, name, fetcher, log):
        folder = OSV_FOLDER[name]
        archive_path = self._scratch() / f"{name}.zip"
        archive_path.unlink(missing_ok=True)
        url = f"{OSV_BUCKET}/{folder}/all.zip"
        log(f"{name}: downloading {url}")
        fetcher.download(url, archive_path, progress=self._progress(log, name), connections=DOWNLOAD_CONNECTIONS)
        building = self.path(name).with_name(self.path(name).name + ".building")
        building.unlink(missing_ok=True)
        newest, count = "", 0
        with closing(sqlite3.connect(building)) as connection:
            connection.executescript(SCHEMA)
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    if not info.filename.endswith(".json"):
                        continue
                    raw = archive.read(info)
                    record = json.loads(raw)
                    _put(connection, record, raw, folder)
                    newest = max(newest, _stamp(record.get("modified", "")))
                    count += 1
            # Built after the bulk insert: maintaining the indexes row by row would slow the load severalfold.
            connection.execute("CREATE INDEX affected_name ON affected(name)")
            connection.execute("CREATE INDEX affected_id ON affected(id)")
            connection.execute("CREATE INDEX cves_cve ON cves(cve)")
            connection.execute("CREATE INDEX cves_id ON cves(id)")
            connection.commit()
        self.close()
        os.replace(building, self.path(name))
        archive_path.unlink()
        return newest, count

    def _osv_cve_index(self, name, log):
        """Copies made before 0.4.0 lack the table of CVE ids; it is built from the records they hold."""
        self.close()
        with closing(sqlite3.connect(self.path(name))) as connection, connection:
            if connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'cves'").fetchone():
                return
            log(f"{name}: indexing the CVE ids of the records held")
            connection.execute("CREATE TABLE cves(cve TEXT, id TEXT)")
            for record_id, body in connection.execute("SELECT id, body FROM records").fetchall():
                connection.executemany("INSERT INTO cves VALUES (?, ?)",
                                       [(c, record_id) for c in sorted(nvd.cve_ids(json.loads(zlib.decompress(body))))])
            connection.execute("CREATE INDEX cves_cve ON cves(cve)")
            connection.execute("CREATE INDEX cves_id ON cves(id)")

    def _osv_changes(self, name, fetcher, since) -> dict[str, str] | None:
        """Records modified at or after ``since`` (id -> time), read from the newest end of OSV's change
        list; None when there are more than an incremental update should fetch."""
        url = f"{OSV_BUCKET}/{OSV_FOLDER[name]}/modified_id.csv"
        changed, offset, pending = {}, 0, b""
        while True:
            status, body = fetcher.read(url, {"Range": f"bytes={offset}-{offset + CSV_CHUNK - 1}"})
            if status == 416:
                break
            if status not in (200, 206):
                raise SyncError(f"{url}: HTTP {status}")
            last = status == 200 or len(body) < CSV_CHUNK
            lines = (pending + body).split(b"\n")
            pending = b"" if last else lines.pop()
            for line in lines:
                stamp, _, record_id = line.decode("utf-8").strip().partition(",")
                if not record_id:
                    continue
                # Listed newest first, so the first entry older than the copy ends the walk. Entries at the
                # copy's own time are fetched again: harmless, and records written in the same instant as
                # the newest one already held are not lost.
                if _stamp(stamp) < since:
                    return changed
                changed.setdefault(record_id, _stamp(stamp))
                if len(changed) > INCREMENTAL_LIMIT:
                    return None
            if last:
                break
            offset += len(body)
        return changed

    def _osv_apply(self, name, changes, entry, fetcher, workers):
        folder = OSV_FOLDER[name]
        answers = map_parallel(lambda i: fetcher.read(f"{OSV_BUCKET}/{folder}/{i}.json"), changes, workers)
        changed = removed = 0
        with closing(sqlite3.connect(self.path(name))) as connection, connection:
            for record_id, (status, body) in zip(changes, answers):
                if status == 404:
                    removed += _drop(connection, record_id)
                elif status == 200:
                    record = json.loads(body)
                    held = connection.execute("SELECT modified FROM records WHERE id = ?", (record_id,)).fetchone()
                    # The walk fetches the records at the copy's own time again; usually they are the ones held.
                    if held is None or held[0] != record.get("modified", ""):
                        _put(connection, record, body, folder, replace=True)
                        changed += 1
                else:
                    raise SyncError(f"OSV record {record_id}: HTTP {status}")
            count = connection.execute("SELECT count(*) FROM records").fetchone()[0]
        newest = max([entry["data_as_of"], *changes.values()])
        if not changed and not removed:
            return {"data_as_of": newest, "records": count}, "up to date"
        detail = f", {removed} removed" if removed else ""
        return ({"data_as_of": newest, "records": count},
                f"updated: {changed} record{'' if changed == 1 else 's'} changed{detail}")

    # ---- KEV ------------------------------------------------------------------------------------------

    def _sync_kev(self, fetcher):
        status, body = fetcher.read(KEV)
        if status != 200:
            raise SyncError(f"{KEV}: HTTP {status}")
        data = json.loads(body)
        count = len(data["vulnerabilities"])
        entry = {"data_as_of": data.get("dateReleased", ""), "records": count}
        held = self.state.get("kev", {}) if self.has("kev") else {}
        # CISA dates every release of the catalog.
        if entry["data_as_of"] and held.get("data_as_of") == entry["data_as_of"]:
            return entry, "up to date"
        temporary = self.path("kev").with_name("kev.json.tmp")
        temporary.write_bytes(body)
        os.replace(temporary, self.path("kev"))
        with self._lock:
            self._kev = None
        return entry, f"downloaded {count} entr{'y' if count == 1 else 'ies'}"

    # ---- Spring ---------------------------------------------------------------------------------------

    def _sync_spring(self, fetcher):
        status, body = fetcher.read(SPRING_ADVISORIES)
        if status != 200:
            raise SyncError(f"{SPRING_ADVISORIES}: HTTP {status}")
        advisories = spring_advisories(json.loads(body))
        text = json.dumps({"advisories": advisories}, sort_keys=True)
        digest = hashlib.sha256(text.encode()).hexdigest()
        entry = {"data_as_of": max((a["published"] for a in advisories.values()), default=""),
                 "records": len(advisories), "digest": digest}
        held = self.state.get("spring", {}) if self.has("spring") else {}
        # spring.io amends advisories without dating the change, so the content tells whether anything changed.
        if held.get("digest") == digest:
            return entry, "up to date"
        temporary = self.path("spring").with_name("spring.json.tmp")
        temporary.write_text(text, "utf-8")
        os.replace(temporary, self.path("spring"))
        with self._lock:
            self._advisories = self._advised = None
        named = sum(1 for a in advisories.values() if a["modules"])
        return entry, f"downloaded {len(advisories)} advisories, {named} of them naming modules"

    # ---- CVE records of the CNAs ---------------------------------------------------------------------

    def _sync_cvelist(self, full, fetcher, log):
        if self.cve_index_missing("osv-maven"):
            raise SyncError("what is kept of the CNAs' records follows the CVEs OSV attributes: install osv-maven "
                            "first (binwitness db sync osv-maven cvelist)")
        tag, day = self._cvelist_latest(fetcher)
        entry = self.state.get("cvelist", {}) if self.has("cvelist") else {}
        osv_as_of = self.data_as_of("osv-maven")
        if not full and entry.get("tag") == tag and entry.get("osv_as_of") == osv_as_of:
            return {}, "up to date"
        behind = (date.fromisoformat(day) - date.fromisoformat(entry["day"])).days if entry.get("day") else None
        self.close()
        if full or behind is None or not 0 <= behind <= CVELIST_DELTA_DAYS:
            return self._cvelist_install(tag, day, fetcher, log)
        try:
            with closing(sqlite3.connect(self.path("cvelist"))) as connection:
                changed = 0
                for offset in range(behind):
                    passed = (date.fromisoformat(entry["day"]) + timedelta(days=offset)).isoformat()
                    changed += self._cvelist_delta(connection, f"cve_{passed}_at_end_of_day",
                                                   f"{passed}_delta_CVEs_at_end_of_day.zip", fetcher)
                    connection.commit()
                changed += self._cvelist_delta(connection, tag, _hourly(tag, day), fetcher)
                finished = self._cvelist_finish(connection, fetcher, log)
        except HttpStatusError as error:
            if error.status != 404:
                raise
            log("cvelist: the changes of a day it lacks are no longer published; downloading the list again")
            return self._cvelist_install(tag, day, fetcher, log)
        return ({**finished, "tag": tag, "day": day, "data_as_of": _tag_time(tag), "osv_as_of": osv_as_of},
                f"updated: {changed} record{'' if changed == 1 else 's'} changed; {finished['links']} product names "
                f"learned{_fetch_note(finished)}")

    def _cvelist_latest(self, fetcher) -> tuple[str, str]:
        """The newest hourly release: its tag (cve_2026-10-30_1100Z) and day."""
        status, body = fetcher.read(cna.RELEASES_FEED)
        if status != 200:
            raise HttpStatusError(cna.RELEASES_FEED, status)
        tags = cna.TAG.findall(body.decode("utf-8", "replace"))
        if not tags:
            raise SyncError(f"{cna.RELEASES_FEED}: lists no release of the CVE list")
        tag, day, _ = max(tags, key=lambda t: (t[1], t[2]))
        return tag, day

    def _cvelist_install(self, tag, day, fetcher, log):
        name = f"{day}_all_CVEs_at_midnight.zip.zip"
        target = self._scratch() / name
        fetcher.download(f"{cna.CVELIST}/releases/download/{tag}/{name}", target, progress=self._progress(log, name),
                         connections=DOWNLOAD_CONNECTIONS)
        building = self.path("cvelist").with_name(self.path("cvelist").name + ".building")
        building.unlink(missing_ok=True)
        stored = 0
        with closing(sqlite3.connect(building)) as connection:
            connection.executescript(CVELIST_SCHEMA)
            for streamed in (True, False):
                try:
                    for raw in _snapshot_files(target, self._scratch(), streamed):
                        stored += _cna_apply(connection, raw, replace=False)
                        if stored % 100000 == 0:
                            log(f"cvelist: {stored} records read")
                    break
                except _Unsized:
                    connection.rollback()
                    stored = 0
            for statement in CVELIST_INDEXES:
                connection.execute(statement)
            connection.commit()
            self._cvelist_delta(connection, tag, _hourly(tag, day), fetcher)
            finished = self._cvelist_finish(connection, fetcher, log)
            # Most records were stored with their text only to learn which ones to keep it of.
            connection.execute("VACUUM")
        os.replace(building, self.path("cvelist"))
        target.unlink(missing_ok=True)
        return ({**finished, "tag": tag, "day": day, "data_as_of": _tag_time(tag), "full_download": _now(),
                 "osv_as_of": self.data_as_of("osv-maven")},
                f"downloaded {finished['records']} records, {finished['kept']} kept with their text; "
                f"{finished['links']} product names learned{_fetch_note(finished)}")

    def _cvelist_delta(self, connection, tag: str, name: str, fetcher) -> int:
        """Apply one release's changed records; how many differ from those stored. An hourly release holds every
        change of its day so far, and a day's end the hours already applied: most may be stored already."""
        target = self._scratch() / name
        fetcher.download(f"{cna.CVELIST}/releases/download/{tag}/{name}", target)
        changed = 0
        with zipfile.ZipFile(target) as archive:
            for info in archive.infolist():
                if not CVE_FILE.search(info.filename):
                    continue
                try:
                    data = json.loads(archive.read(info))
                except ValueError:
                    continue
                record = cna.trim(data) if isinstance(data, dict) else None
                if record is None:
                    continue
                held = connection.execute("SELECT updated FROM records WHERE id = ?", (record["id"],)).fetchone()
                if record["state"] == "PUBLISHED":
                    changed += held is None or held[0] != record["updated"]
                else:
                    changed += held is not None
                _cna_apply(connection, data)
        target.unlink()
        return changed

    def _cvelist_finish(self, connection, fetcher, log) -> dict:
        """Keep the text of the records a candidate may come from, fetch it for those that became so since, and
        learn the product names of packages from the CVEs OSV attributes.

        A record is kept with its text when OSV attributes its CVE to a Maven package (learning reads it), when it
        names a Maven package or a CPE, when it names a product that a CVE OSV attributes names too, or when a
        vendor's advisory names a module; of the others, a fifth of the list, only what tells whether they become
        so."""
        attributed: dict[str, set[str]] = {}
        for cve, name in self._rows("osv-maven", "SELECT c.cve, a.name FROM cves c JOIN affected a ON a.id = c.id",
                                    ()):
            attributed.setdefault(cve, set()).add(name)
        connection.execute("CREATE TEMP TABLE attributed(id TEXT PRIMARY KEY)")
        connection.executemany("INSERT INTO attributed VALUES (?)", [(c,) for c in sorted(attributed)])
        connection.execute("CREATE TEMP TABLE advised(id TEXT PRIMARY KEY)")
        connection.executemany("INSERT INTO advised VALUES (?)", [(c,) for c in self._advised_cves()])
        connection.executescript("""
            CREATE TEMP TABLE known AS SELECT DISTINCT key FROM keys WHERE id IN (SELECT id FROM attributed);
            CREATE TEMP TABLE kept(id TEXT PRIMARY KEY);
            INSERT OR IGNORE INTO kept SELECT id FROM attributed;
            INSERT OR IGNORE INTO kept SELECT id FROM packages;
            INSERT OR IGNORE INTO kept SELECT id FROM cpes;
            INSERT OR IGNORE INTO kept SELECT id FROM keys WHERE key IN (SELECT key FROM known);
            INSERT OR IGNORE INTO kept SELECT id FROM advised WHERE id IN (SELECT id FROM records);
            UPDATE records SET body = NULL WHERE body IS NOT NULL AND id NOT IN (SELECT id FROM kept);
        """)
        connection.commit()
        wanted = [i for (i,) in connection.execute("SELECT id FROM records WHERE body IS NULL AND id IN "
                                                   "(SELECT id FROM kept) ORDER BY id DESC")]
        fetched = self._cvelist_fetch(connection, wanted[:CVELIST_FETCH_LIMIT], fetcher, log)
        keys: dict[str, list[tuple[str, dict]]] = {}
        for ident, body in connection.execute("SELECT r.id, r.body FROM records r JOIN attributed a ON a.id = r.id "
                                              "WHERE r.body IS NOT NULL"):
            record = json.loads(zlib.decompress(body))
            found = [(key, e) for e in record["affected"] if cna.usable(e)
                     for key in [cna.key_of(e["vendor"], e["product"])] if key]
            if found:
                keys[ident] = found
        links = cna.learn({c: n for c, n in attributed.items()}, keys, lambda n: self.osv_records("maven", n))
        connection.execute("DELETE FROM links")
        connection.executemany("INSERT INTO links VALUES (?, ?, ?)",
                               [(k, n, c) for k, found in sorted(links.items()) for n, c in sorted(found.items())])
        for table in ("kept", "known", "attributed", "advised"):
            connection.execute(f"DROP TABLE temp.{table}")
        connection.commit()
        count = lambda sql: connection.execute(sql).fetchone()[0]
        return {"records": count("SELECT count(*) FROM records"),
                "kept": count("SELECT count(*) FROM records WHERE body IS NOT NULL"),
                "links": count("SELECT count(DISTINCT key) FROM links"),
                "bodies_not_fetched": len(wanted) - fetched}

    def _cvelist_fetch(self, connection, ids: list[str], fetcher, log) -> int:
        """Fetch records one by one from the repository; how many were."""
        failures, lock = [0], threading.Lock()

        def read(ident):
            if failures[0] >= CVELIST_FAILURES_TO_STOP:
                return None
            try:
                status, body = fetcher.read(cna.raw_url(ident))
            except SyncError:
                status, body = None, None
            with lock:
                failures[0] = 0 if status == 200 else failures[0] + 1
            return body if status == 200 else None
        done = 0
        for start in range(0, len(ids), FIX_BATCH * 5):
            batch = ids[start:start + FIX_BATCH * 5]
            for body in map_parallel(read, batch, CVELIST_WORKERS):
                if body is not None:
                    _cna_apply(connection, body)
                    done += 1
            connection.commit()
            if len(ids) > len(batch):
                log(f"cvelist: {min(start + len(batch), len(ids))} of {len(ids)} records fetched")
        return done

    # ---- fix commits ----------------------------------------------------------------------------------

    def _sync_fixes(self, fetcher, log):
        if not (self.has("nvd") and self.has("osv-maven")):
            raise SyncError("fixes are read from the NVD records of Maven packages: install nvd and osv-maven first "
                            "(binwitness db sync nvd osv-maven fixes)")
        try:
            stored = json.loads(self.path("fixes").read_text("utf-8"))
        except (OSError, ValueError):
            stored = {}
        pages = self._vendor_pages(fetcher, stored.get("pages") or {}, log)
        records = self._fix_records(pages)
        cited = {key for entry in records.values() for key in entry["commits"]}
        # A commit does not change once made: what was read stays, also from a sync that was interrupted, and only
        # commits not read before are fetched; and those an older reader may have read short.
        held = stored.get("commits") or {}
        commits = {key: value for key, value in held.items() if key in cited and not fixes.stale(value)}
        wanted = sorted(cited - commits.keys())
        failures, lock = [0], threading.Lock()

        def read(key):
            # GitHub limits what one address may fetch; once it keeps refusing, asking on only waits out each retry.
            if failures[0] >= FIX_FAILURES_TO_STOP:
                return None
            answer = self._read_fix(fetcher, key)
            with lock:
                failures[0] = failures[0] + 1 if answer is None else 0
            return answer
        for start in range(0, len(wanted), FIX_BATCH):
            batch = wanted[start:start + FIX_BATCH]
            commits.update((k, v) for k, v in zip(batch, map_parallel(read, batch, FIX_WORKERS)) if v is not None)
            self._write_fixes(records, commits, pages)
            log(f"fixes: {min(start + FIX_BATCH, len(wanted))} of {len(wanted)} commits fetched")
        self._write_fixes(records, commits, pages)
        pending = len(cited - commits.keys())
        entry = {"data_as_of": self.state["nvd"].get("data_as_of", ""), "records": len(records),
                 "commits": len(commits), "commits_not_read": pending}
        # The CNAs' records cite commits too, of CVEs NVD has given no CPE yet: often the newest.
        alone = "" if self.has("cvelist") else "; without cvelist, the commits the CNAs' records cite are not read"
        if not wanted:
            return entry, f"up to date: {len(commits)} commits cited by {len(records)} records{alone}"
        fetched = len(wanted) - pending
        outcome = f"fetched {fetched} commit{'' if fetched == 1 else 's'}; {len(commits)} of the {len(cited)} cited " \
                  f"by {len(records)} records held"
        if pending:
            outcome += (f"; {pending} not fetched ("
                        + ("GitHub stopped answering" if failures[0] >= FIX_FAILURES_TO_STOP else "downloads failed")
                        + "): sync fixes again later")
        return entry, outcome + alone

    def _fixes_unread(self) -> int:
        """How many of the commits the records cite now the fixes dataset has not read."""
        try:
            stored = json.loads(self.path("fixes").read_text("utf-8"))
            records = self._fix_records(stored.get("pages") or {})
        except (OSError, ValueError, KeyError, sqlite3.Error):
            return 0
        held = stored.get("commits") or {}
        cited = {key for entry in records.values() for key in entry["commits"]}
        return sum(1 for key in cited if key not in held or fixes.stale(held[key]))

    def _read_fix(self, fetcher, key: str) -> dict | None:
        """A commit as ``fixes.read_diff`` reads it; ``{"unread": "not found"}`` when GitHub has no such commit,
        None when it could not be fetched now."""
        url = fixes.commit_url(key) + ".diff"

        def attempt():
            status, _, stream = fetcher.opener(url, {"Accept": "text/plain"})
            with closing(stream):
                if status != 200:
                    return status, None
                return 200, fixes.read_diff(iter(lambda: stream.readline(1 << 16), b""))
        # Not fetcher.read: a 429 there means a quota for the day, while GitHub's passes in a minute or two.
        try:
            status, answer = fetcher._retry(url, attempt)
        except SyncError:
            return None
        if status in (404, 410, 422):
            return {"unread": "not found"}
        return answer if status == 200 else None

    def _vendor_pages(self, fetcher, held: dict, log) -> dict[str, dict[str, list[str]]]:
        """Page URL -> CVE id -> the commits a vendor's security page gives as its fix; a page that cannot be
        fetched now keeps what was read of it before."""
        pages = {}
        for url in fixes.VENDOR_PAGES:
            try:
                status, body = fetcher.read(url)
            except SyncError:
                status, body = None, None
            if status == 200:
                pages[url] = fixes.page_commits(body.decode("utf-8", "replace"))
            else:
                log(f"fixes: {url} could not be fetched ({status or 'no answer'}); keeping what was read of it before")
                pages[url] = held.get(url) or {}
        return pages

    def _fix_records(self, pages: dict | None = None) -> dict[str, dict]:
        """Record id -> the commits it cites, for the records that can become candidates of a Maven package: not
        attributed by OSV, with a CPE that some CVE OSV does attribute carries, or (from the CNAs' records) a product
        name or package that some such CVE names. Only commits in a repository those attributed CVEs refer to are
        read; the others are kept apart, since a record may cite the fix of another product (one that bundles the
        library). A vendor's security page gives the commits of its own product: they count as the patch."""
        attributed = {c for (c,) in self._rows("osv-maven", "SELECT DISTINCT cve FROM cves", ())}
        # Only the CPEs of attributed CVEs, and the records that carry one of them, are read: all of NVD's CPEs
        # held at once took some 170 MB.
        attributed_cpes = self.nvd_cpes(attributed)
        repositories: dict[str, set[str]] = {}
        for ident in sorted(attributed_cpes):
            record = self.nvd_record(ident) or {}
            cited = fixes.repositories_cited([*record.get("references", []),
                                              *(url for url, _ in record.get("fix_refs") or [])])
            for cpe in attributed_cpes[ident]:
                repositories.setdefault(cpe, set()).update(cited)
        linked_cpes: dict[str, list[str]] = {}
        for cpe in sorted(repositories):
            for ident in self.nvd_ids(cpe):
                if ident not in attributed:
                    linked_cpes.setdefault(ident, []).append(cpe)
        out = {}
        for ident in sorted(linked_cpes):
            linked = [repositories[cpe] for cpe in linked_cpes[ident]]
            record = self.nvd_record(ident) or {}
            # Records stored before 0.4.4 keep the first references only, and not the tags NVD gave them.
            refs = record.get("fix_refs")
            cited = fixes.commits_cited([url for url, _ in refs] if refs is not None else record.get("references", []))
            if not cited:
                continue
            known = set().union(*linked)
            entry = {"commits": [f"{r}@{s}" for r, s in cited if r in known],
                     "elsewhere": [fixes.commit_url(f"{r}@{s}") for r, s in cited if r not in known], "patch": None}
            if refs is not None:
                tagged = {f"{r}@{s}" for r, s in fixes.commits_cited([url for url, patch in refs if patch])}
                entry["patch"] = [key for key in entry["commits"] if key in tagged]
            out[ident] = entry
        if self.has("cvelist"):
            self._cna_fix_records(attributed, out)
        for found in (pages or {}).values():
            for ident, keys in sorted(found.items()):
                if ident in attributed:
                    continue
                entry = out.setdefault(ident, {"commits": [], "elsewhere": [], "patch": None})
                entry["commits"] = list(dict.fromkeys([*entry["commits"], *keys]))
                entry["patch"] = list(dict.fromkeys([*(entry["patch"] or []), *keys]))
        return out

    def _cna_fix_records(self, attributed: set[str], out: dict):
        """The commits the CNAs' records of CVEs NVD has given no CPE cite, in the repositories that the CVEs OSV
        attributes and whose records name the same product or package refer to."""
        repositories: dict[str, set[str]] = {}
        backlog: list[dict] = []
        last = 0
        while rows := self._rows("cvelist", "SELECT rowid, body FROM records WHERE body IS NOT NULL AND rowid > ? "
                                 "ORDER BY rowid LIMIT ?", (last, RECORD_PAGE)):
            last = rows[-1][0]
            for _, body in rows:
                record = json.loads(zlib.decompress(body))
                keys, packages, _ = cna.facets(record)
                names = keys | {cna.module_key(p) for p, _ in packages}
                if record["id"] in attributed:
                    cited = fixes.repositories_cited(record["references"]) | fixes.repositories_cited(
                        (self.nvd_record(record["id"]) or {}).get("references", []))
                    for name in names:
                        repositories.setdefault(name, set()).update(cited)
                elif record["id"] not in out and record["commits"] and names:
                    backlog.append({"id": record["id"], "names": names, "commits": record["commits"]})
        with_cpe = self.nvd_cpes([record["id"] for record in backlog])
        for record in backlog:
            if record["id"] in with_cpe:
                continue
            known = set().union(*(repositories.get(n, set()) for n in record["names"]))
            if not known:
                continue
            cited = fixes.commits_cited(record["commits"])
            out[record["id"]] = {"commits": [f"{r}@{s}" for r, s in cited if r in known],
                                 "elsewhere": [fixes.commit_url(f"{r}@{s}") for r, s in cited if r not in known],
                                 "patch": None}

    def _write_fixes(self, records: dict, commits: dict, pages: dict | None = None):
        temporary = self.path("fixes").with_name("fixes.json.tmp")
        temporary.write_text(json.dumps({"records": records, "commits": commits, "pages": pages or {}},
                                        sort_keys=True), "utf-8")
        os.replace(temporary, self.path("fixes"))
        with self._lock:
            self._fixes = None

    # ---- NVD ------------------------------------------------------------------------------------------

    def _sync_nvd(self, full, fetcher, log):
        entry = self.state.get("nvd", {}) if self.has("nvd") else {}
        current = entry.get("layout") == nvd.LAYOUT
        if not full and entry and current and time.time() - _epoch(entry["data_as_of"]) < NVD_MODIFIED_DAYS * 86400:
            return self._nvd_update(entry, fetcher, log)
        if entry and not current:
            log("nvd: stored by an earlier version without the fix commits' tags; downloading it again (about "
                "235 MB). The copy held stays in use until it is done, and is kept if the download fails")
        building = self.path("nvd").with_name(self.path("nvd").name + ".building")
        building.unlink(missing_ok=True)
        newest, stored = "", 0
        names = [f"nvdcve-2.0-{year}" for year in range(nvd.FIRST_YEAR, datetime.now(timezone.utc).year + 1)]
        scratch = self._scratch()
        # Newest first: the recent years are the largest, and started last one of them would finish alone.
        map_parallel(lambda name: fetcher.download(f"{nvd.NVD_FEEDS}/{name}.json.gz", scratch / f"{name}.json.gz",
                                                   progress=self._progress(log, name)), names[::-1], NVD_WORKERS)
        with closing(sqlite3.connect(building)) as connection:
            connection.executescript(nvd.SCHEMA)
            for name in names:
                (feed_newest, feed_stored, _), _ = self._nvd_feed(connection, name, fetcher, log, fetched=True)
                newest, stored = max(newest, feed_newest), stored + feed_stored
            # Built after the bulk insert, as for OSV.
            connection.execute("CREATE INDEX cpes_product ON cpes(vendor, product)")
            connection.execute("CREATE INDEX cpes_id ON cpes(id)")
            connection.commit()
            entry = self._nvd_entry(connection, newest)
        self.close()
        os.replace(building, self.path("nvd"))
        return ({**entry, "full_download": _now(), "modified_sha256": None, "layout": nvd.LAYOUT},
                f"downloaded {stored} records with a CPE")

    def _nvd_update(self, entry, fetcher, log):
        meta = self._nvd_meta("nvdcve-2.0-modified", fetcher)
        if meta.get("sha256") and meta["sha256"] == entry.get("modified_sha256"):
            return {}, "up to date"
        self.close()
        with closing(sqlite3.connect(self.path("nvd"))) as connection:
            (newest, stored, removed), meta = self._nvd_feed(connection, "nvdcve-2.0-modified", fetcher, log, meta,
                                                             replace=True)
            entry = self._nvd_entry(connection, max(newest, entry["data_as_of"]))
        return ({**entry, "modified_sha256": meta.get("sha256")},
                f"updated: {stored} record{'' if stored == 1 else 's'} with a CPE written, {removed} replaced or removed")

    @staticmethod
    def _nvd_entry(connection, newest) -> dict:
        return {"data_as_of": newest, "records": connection.execute("SELECT count(*) FROM records").fetchone()[0],
                "without_cpe": dict(connection.execute("SELECT status, count(*) FROM unanalyzed GROUP BY status "
                                                       "ORDER BY status").fetchall())}

    @staticmethod
    def _nvd_meta(name, fetcher) -> dict:
        url = f"{nvd.NVD_FEEDS}/{name}.meta"
        status, body = fetcher.read(url)
        if status != 200:
            raise HttpStatusError(url, status)
        fields = dict(line.partition(":")[::2] for line in body.decode("utf-8").splitlines() if ":" in line)
        return {k.strip(): v.strip() for k, v in fields.items()}

    def _nvd_feed(self, connection, name, fetcher, log, meta=None, replace=False, fetched=False):
        """Load one feed: ((newest modification, records stored, records dropped first), its .meta). The feed
        is checked against the digest in the .meta while it is read. One that does not match (left by an
        earlier attempt, or regenerated in between) is downloaded once more. ``fetched``: it was just
        downloaded."""
        target = self._scratch() / f"{name}.json.gz"
        for attempt in (1, 2):
            meta = meta or self._nvd_meta(name, fetcher)
            if not (fetched and attempt == 1):
                fetcher.download(f"{nvd.NVD_FEEDS}/{name}.json.gz", target, progress=self._progress(log, name),
                                 connections=DOWNLOAD_CONNECTIONS)
            loaded, digest = _nvd_load(connection, target, replace)
            if not meta.get("sha256") or digest.upper() == meta["sha256"].upper():
                connection.commit()
                return loaded, meta
            connection.rollback()
            target.unlink()
            meta = None
        raise SyncError(f"{name}: the feed does not match the digest in its .meta")

    # ---- Maven Central hash index ---------------------------------------------------------------------

    def _sync_maven_hashes(self, full, every_days, fetcher, log):
        installed = self.state.get("maven-hashes", {}) if self.has("maven-hashes") else {}
        base_as_of = installed.get("base_as_of") or installed.get("data_as_of")
        if full or not base_as_of or time.time() - _epoch(base_as_of) >= every_days * 86400:
            entry, outcome = self._hashes_base(full, fetcher, log)
            if entry:
                # Recorded before the additions are fetched: if those fail, the next sync must not take the old
                # additions for this base's.
                installed = self.state["maven-hashes"] = {**installed, **entry, "synced": _now()}
                self._write_state()
        else:
            outcome = f"base of {base_as_of[:10]} kept (downloaded again after {every_days:g} days)"
        checked = installed.get("checked")
        if checked and installed.get("chunk") is not None and time.time() - _epoch(checked) < CENTRAL_CHECK_DAYS * 86400:
            return {}, f"{outcome}; Central's additions checked on {checked[:10]} (again after {CENTRAL_CHECK_DAYS} days)"
        added, added_outcome = self._hashes_additions(installed, fetcher, log)
        return added, f"{outcome}; {added_outcome}"

    def _hashes_base(self, full, fetcher, log):
        """Trivy's snapshot of the index."""
        def auth():
            status, body = fetcher.read(f"{GHCR}/token?scope=repository:{JAVA_DB}:pull")
            if status != 200:
                raise SyncError(f"{GHCR} token: HTTP {status}")
            return {"Authorization": f"Bearer {json.loads(body)['token']}"}

        status, manifest_bytes = fetcher.read(f"{GHCR}/v2/{JAVA_DB}/manifests/{JAVA_DB_TAG}",
                                              {**auth(), "Accept": OCI_MANIFEST})
        if status != 200:
            raise SyncError(f"{JAVA_DB} manifest: HTTP {status}")
        digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        manifest = json.loads(manifest_bytes)
        created = (manifest.get("annotations") or {}).get("org.opencontainers.image.created", "")
        if not full and self.has("maven-hashes") and self.state["maven-hashes"].get("digest") == digest:
            return {}, "up to date"
        layer = next((x for x in manifest.get("layers", []) if x.get("mediaType") == JAVA_DB_LAYER), None)
        if layer is None:
            raise SyncError(f"{JAVA_DB}: no layer of type {JAVA_DB_LAYER}; the publication format has changed")
        scratch = self._scratch()
        # Named by content digest: a later run resumes this download, and never mixes in another release.
        # The registry's tokens expire within minutes, sooner than a slow line downloads the layer, so every
        # resumption asks for a fresh one.
        archive_path = scratch / f"{layer['digest'].replace(':', '-')}.tar.gz"
        for stale in scratch.glob("sha256-*.tar.gz"):
            if stale != archive_path:
                stale.unlink()
        log(f"maven-hashes: downloading {layer['size'] / 2**20:.0f} MB from ghcr.io/{JAVA_DB}")
        fetcher.download(f"{GHCR}/v2/{JAVA_DB}/blobs/{layer['digest']}", archive_path, auth, sha256=layer["digest"],
                         progress=self._progress(log, "maven-hashes"), connections=DOWNLOAD_CONNECTIONS)
        building = self.path("maven-hashes").with_name(DATASETS["maven-hashes"].file + ".building")
        with tarfile.open(archive_path, "r:gz") as archive:
            member = next((m for m in archive if m.isfile() and posixpath.basename(m.name) == "trivy-java.db"), None)
            if member is None:
                raise SyncError(f"{JAVA_DB}: trivy-java.db not found in the layer")
            with archive.extractfile(member) as source, building.open("wb") as out:
                shutil.copyfileobj(source, out, 1 << 20)
        with closing(sqlite3.connect(building)) as connection:
            columns = {r[1] for r in connection.execute("PRAGMA table_info(indices)")}
            if not {"artifact_id", "version", "sha1", "archive_type"} <= columns:
                building.unlink()
                raise SyncError(f"{JAVA_DB}: unexpected table layout {sorted(columns)}")
            count = connection.execute("SELECT max(rowid) FROM indices").fetchone()[0] or 0
        self.close()
        os.replace(building, self.path("maven-hashes"))
        (self.directory / RECENT_FILE).unlink(missing_ok=True)
        archive_path.unlink()
        return ({"digest": digest, "base_as_of": created, "base_records": count, "data_as_of": created,
                 "records": count, "chain": None, "chunk": None, "recent_records": 0},
                f"downloaded {count} jar hashes")

    def _hashes_additions(self, installed, fetcher, log):
        """Maven Central's weekly additions published since the base, kept in a small side database."""
        status, body = fetcher.read(INDEX_PROPERTIES)
        if status != 200:
            raise SyncError(f"{INDEX_PROPERTIES}: HTTP {status}")
        properties = dict(line.split("=", 1) for line in body.decode("utf-8", "replace").splitlines()
                          if "=" in line and not line.startswith("#"))
        chain = properties.get("nexus.index.chain-id")
        last = int(properties.get("nexus.index.last-incremental", "-1"))
        listed = sorted(int(v) for k, v in properties.items() if k.startswith("nexus.index.incremental-") and v.isdigit())
        base_as_of = installed.get("base_as_of") or installed["data_as_of"]
        base_records = installed.get("base_records") or installed.get("records") or 0
        applied = installed.get("chunk")
        if applied is not None and installed.get("chain") != chain:
            raise SyncError("Maven Central restarted its index; run `binwitness db sync maven-hashes --full`")
        if applied is not None:
            pending = list(range(applied + 1, last + 1))
            if any(n not in listed for n in pending):
                raise SyncError("the copy is older than the weekly additions Maven Central still lists; "
                                "run `binwitness db sync maven-hashes --full`")
        else:
            since = _epoch(base_as_of) - CHUNK_OVERLAP
            pending = []
            for number in reversed(listed):
                if _chunk_time(fetcher, number) <= since:
                    break
                pending.insert(0, number)
            else:
                raise SyncError("the base is older than the weekly additions Maven Central still lists; "
                                "run `binwitness db sync maven-hashes --full`")
        entry = {"base_as_of": base_as_of, "base_records": base_records, "chain": chain,
                 "chunk": applied if applied is not None else last, "data_as_of": installed.get("data_as_of") or base_as_of,
                 "records": base_records + (installed.get("recent_records") or 0),
                 "recent_records": installed.get("recent_records") or 0}
        self.close()
        with closing(sqlite3.connect(self.directory / RECENT_FILE)) as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS hashes(sha1 BLOB, group_id TEXT, artifact_id TEXT, version TEXT, "
                "classifier TEXT, UNIQUE(sha1, group_id, artifact_id, version, classifier));"
                "CREATE INDEX IF NOT EXISTS hashes_sha1 ON hashes(sha1);")
            for number in pending:
                chunk = self._scratch() / f"central-index-{chain}-{number}.gz"
                try:
                    fetcher.download(f"{CENTRAL_INDEX}/nexus-maven-repository-index.{number}.gz", chunk,
                                     progress=self._progress(log, f"maven-hashes: Central additions #{number}"))
                except HttpStatusError as error:
                    if error.status != 404:
                        raise
                    raise SyncError(f"Maven Central no longer serves addition #{number}; "
                                    "run `binwitness db sync maven-hashes --full`") from None
                stamp, rows = _index_jars(chunk)
                with connection:
                    connection.executemany("INSERT OR IGNORE INTO hashes VALUES (?, ?, ?, ?, ?)", rows)
                chunk.unlink()
                recent = connection.execute("SELECT count(*) FROM hashes").fetchone()[0]
                entry.update(chunk=number, records=base_records + recent, recent_records=recent)
                if _epoch(stamp) > _epoch(entry["data_as_of"]):
                    entry["data_as_of"] = stamp
                # Recorded chunk by chunk: a sync stopped by the rate limit must not download these again.
                self.state["maven-hashes"] = {**installed, **entry, "synced": _now()}
                self._write_state()
        outcome = (f"applied Central's additions #{pending[0]}-#{pending[-1]}" if pending
                   else "no new additions on Central")
        return {**entry, "checked": _now()}, outcome


def _epoch(stamp: str) -> float:
    # Publishers state UTC with anything from no fraction to nanoseconds; seconds are enough here.
    return datetime.fromisoformat(stamp[:19]).replace(tzinfo=timezone.utc).timestamp()


def _iso(milliseconds: int) -> str:
    return datetime.fromtimestamp(milliseconds / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chunk_time(fetcher: Fetcher, number: int) -> float:
    """When a chunk of the Central index was cut, from its first bytes."""
    status, head = fetcher.read(f"{CENTRAL_INDEX}/nexus-maven-repository-index.{number}.gz", {"Range": "bytes=0-4095"})
    if status not in (200, 206):
        raise SyncError(f"Central index chunk {number}: HTTP {status}")
    start = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(head[:4096])
    return struct.unpack(">q", start[1:9])[0] / 1000


class _Reader:
    """Exact-size reads over a decompressing stream; per-call overhead dominates with records this small."""

    def __init__(self, stream, what: str = "Central index chunk"):
        self.stream, self.buffer, self.offset, self.what = stream, b"", 0, what

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.buffer):
            self.buffer = self.buffer[self.offset:] + self.stream.read(max(size, 4 << 20))
            self.offset, end = 0, size
            if end > len(self.buffer):
                if self.buffer:
                    raise EOFError(f"{self.what} ends inside a record")
                return b""
        data = self.buffer[self.offset:end]
        self.offset = end
        return data

    def number(self, form: str) -> int:
        data = self.take(struct.calcsize(form))
        if not data:
            raise EOFError(f"{self.what} ends inside a record")
        return struct.unpack(form, data)[0]


def _index_jars(path: Path) -> tuple[str, list[tuple]]:
    """Cut time and (sha1, group, artifact, version, classifier) of the jars in a chunk of the Central index.

    The chunk is in the Maven Indexer format: a version byte and a timestamp, then records of named fields.
    ``u`` is ``group|artifact|version|classifier[|extension]`` (classifier ``NA`` for none, extension then
    taken from the last field of ``i``) and ``1`` the SHA-1. gzip's trailer check rejects a truncated file.
    """
    rows = []
    with gzip.open(path, "rb") as stream:
        reader = _Reader(stream)
        reader.number(">b")
        milliseconds = reader.number(">q")
        while count := reader.take(4):
            fields = {}
            for _ in range(struct.unpack(">i", count)[0]):
                reader.number(">b")
                name = reader.take(reader.number(">H"))
                fields[name] = reader.take(reader.number(">i"))
            row = _index_jar(fields)
            if row:
                rows.append(row)
    return _iso(milliseconds), rows


def _index_jar(fields: dict[bytes, bytes]) -> tuple | None:
    parts = fields.get(b"u", b"").decode("utf-8", "replace").split("|")
    sha1 = fields.get(b"1", b"").decode("ascii", "replace")
    if len(parts) < 4 or len(sha1) != 40:
        return None
    extension = parts[4] if len(parts) > 4 else fields.get(b"i", b"").decode("utf-8", "replace").split("|")[-1]
    # Sources and javadoc are never deployed, and the base leaves them out too.
    if extension != "jar" or parts[3] in ("sources", "javadoc"):
        return None
    try:
        key = bytes.fromhex(sha1)
    except ValueError:
        return None
    return key, parts[0], parts[1], parts[2], "" if parts[3] == "NA" else parts[3]


class _Digesting(io.RawIOBase):
    """A stream that takes the SHA-256 of what is read through it."""

    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.stream.read(len(buffer))
        self.digest.update(data)
        buffer[:len(data)] = data
        return len(data)


def _nvd_load(connection, path: Path, replace: bool) -> tuple[tuple[str, int, int], str]:
    """Rejected records are left out, and so are records without a CPE of an application, which are counted
    by status instead."""
    newest, stored, removed = "", 0, 0
    with gzip.open(path, "rb") as compressed:
        digesting = _Digesting(compressed)
        for cve in nvd.feed_items(io.BufferedReader(digesting)):
            ident = cve.get("id")
            if not ident:
                continue
            newest = max(newest, _stamp(cve.get("lastModified", "")))
            if replace:
                connection.execute("DELETE FROM cpes WHERE id = ?", (ident,))
                connection.execute("DELETE FROM unanalyzed WHERE id = ?", (ident,))
                removed += connection.execute("DELETE FROM records WHERE id = ?", (ident,)).rowcount
            status = cve.get("vulnStatus") or ""
            if status == "Rejected":
                continue
            if not cve.get("configurations"):
                connection.execute("INSERT OR REPLACE INTO unanalyzed VALUES (?, ?)", (ident, status))
                continue
            record = nvd.compact(cve)
            if not record["matches"]:
                continue
            connection.execute("INSERT OR REPLACE INTO records VALUES (?, ?, ?, ?)",
                               (ident, cve.get("lastModified", ""), status,
                                zlib.compress(json.dumps(record, separators=(",", ":")).encode("utf-8"))))
            connection.executemany("INSERT INTO cpes VALUES (?, ?, ?)",
                                   sorted({(m["vendor"], m["product"], ident) for m in record["matches"]}))
            stored += 1
    return (newest, stored, removed), digesting.digest.hexdigest()


def _batches(items: list, size: int = ID_BATCH):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _marks(batch: list) -> str:
    return ", ".join("?" * len(batch))


def _put(connection, record: dict, raw: bytes, folder: str, replace: bool = False):
    record_id = record["id"]
    if replace:
        _drop(connection, record_id)
    connection.execute("INSERT INTO records VALUES (?, ?, ?, ?)",
                       (record_id, record.get("modified", ""), 1 if record.get("withdrawn") else 0,
                        zlib.compress(raw)))
    names = {a["package"]["name"] for a in record.get("affected", [])
             if (a.get("package") or {}).get("ecosystem") == folder and a["package"].get("name")}
    connection.executemany("INSERT INTO affected VALUES (?, ?)", [(n, record_id) for n in sorted(names)])
    connection.executemany("INSERT INTO cves VALUES (?, ?)", [(c, record_id) for c in sorted(nvd.cve_ids(record))])


def _drop(connection, record_id: str) -> int:
    connection.execute("DELETE FROM affected WHERE id = ?", (record_id,))
    connection.execute("DELETE FROM cves WHERE id = ?", (record_id,))
    return connection.execute("DELETE FROM records WHERE id = ?", (record_id,)).rowcount


def _hourly(tag: str, day: str) -> str:
    return f"{day}_delta_CVEs_at_{tag.rsplit('_', 1)[1]}.zip"


def _tag_time(tag: str) -> str:
    """cve_2026-10-30_1100Z as 2026-10-30T11:00:00Z."""
    found = cna.TAG.search(f"releases/tag/{tag}")
    return f"{found.group(2)}T{found.group(3)[:2]}:{found.group(3)[2:]}:00Z" if found else ""


def _fetch_note(finished: dict) -> str:
    pending = finished["bodies_not_fetched"]
    return f"; {pending} records still to fetch: sync cvelist again later" if pending else ""


def _cna_apply(connection, raw: bytes | dict, replace: bool = True) -> int:
    """Store a CVE JSON 5 record, or drop it when it is no longer published; 1 when stored."""
    try:
        data = json.loads(raw) if isinstance(raw, (bytes, str)) else raw
    except ValueError:
        return 0
    record = cna.trim(data) if isinstance(data, dict) else None
    if record is None:
        return 0
    ident = record["id"]
    if replace:
        for table in ("keys", "packages", "cpes", "records"):
            connection.execute(f"DELETE FROM {table} WHERE id = ?", (ident,))
    if record["state"] != "PUBLISHED":
        return 0
    keys, packages, cpes = cna.facets(record)
    connection.execute("INSERT INTO records VALUES (?, ?, ?, ?, ?)",
                       (ident, record["cna"], record["published"], record["updated"],
                        zlib.compress(json.dumps(record, separators=(",", ":")).encode("utf-8"))))
    connection.executemany("INSERT INTO keys VALUES (?, ?)", [(k, ident) for k in sorted(keys)])
    connection.executemany("INSERT INTO packages VALUES (?, ?, ?, ?)",
                           [(n, cna.module_key(n), ident, how) for n, how in sorted(packages)])
    connection.executemany("INSERT INTO cpes VALUES (?, ?, ?)", [(*c.split(":", 1), ident) for c in sorted(cpes)])
    return 1


class _Unsized(Exception):
    """A zip entry whose sizes follow its data: it cannot be read as the zip streams past."""


def _snapshot_files(path: Path, scratch: Path, streamed: bool = True) -> Iterator[bytes]:
    """The record files of a cvelistV5 snapshot, a zip that holds one zip (cves.zip) of 400,000 records. The
    inner zip is read as it is decompressed rather than unpacked to disk first (``streamed``); that raises
    _Unsized at an entry whose sizes follow its data, and then it has to be unpacked."""
    unpacked = scratch / "cves.zip"
    with zipfile.ZipFile(path) as outer:
        inner = next((i for i in outer.infolist() if i.filename.endswith(".zip")), None)
        if inner is None:
            raise SyncError(f"{path.name}: holds no zip of records")
        if streamed:
            with outer.open(inner) as stream:
                yield from _local_entries(_Reader(stream, inner.filename))
            return
        with outer.open(inner) as stream, unpacked.open("wb") as out:
            shutil.copyfileobj(stream, out, 1 << 20)
    try:
        with zipfile.ZipFile(unpacked) as archive:
            for info in archive.infolist():
                if CVE_FILE.search(info.filename):
                    yield archive.read(info)
    finally:
        unpacked.unlink(missing_ok=True)


def _local_entries(reader) -> Iterator[bytes]:
    """The record files of a zip read front to back, by the header before each entry."""
    while True:
        head = reader.take(30)
        if head[:4] != b"PK\x03\x04":
            return  # the central directory
        if len(head) < 30:
            raise EOFError(f"{reader.what} ends inside an entry")
        _, _, flags, method, _, _, _, size, _, name_size, extra_size = struct.unpack("<IHHHHHIIIHH", head)
        name = reader.take(name_size).decode("utf-8", "replace")
        extra = reader.take(extra_size)
        if flags & 0x08:
            raise _Unsized(name)
        if flags & 0x01:
            raise SyncError(f"{name}: encrypted")
        if size == 0xFFFFFFFF:
            size = _zip64_size(extra)
        data = reader.take(size)
        if len(data) < size:
            raise EOFError(f"{reader.what} ends inside {name}")
        if not CVE_FILE.search(name):
            continue
        if method == 8:
            data = zlib.decompress(data, -15)
        elif method != 0:
            raise SyncError(f"{name}: compressed by method {method}")
        yield data


def _zip64_size(extra: bytes) -> int:
    offset = 0
    while offset + 4 <= len(extra):
        tag, length = struct.unpack_from("<HH", extra, offset)
        if tag == 1 and length >= 16:
            return struct.unpack_from("<QQ", extra, offset + 4)[1]
        offset += 4 + length
    raise SyncError("a zip entry states its size in a form not known")


def spring_advisories(page: dict) -> dict[str, dict]:
    """CVE id -> the modules, affected versions, project and publication date of its advisory, from the data
    behind spring.io's security page. That data serves the site, not clients: a layout this does not know is refused rather than
    read as no advisories."""
    try:
        nodes = page["result"]["data"]["cves"]["nodes"]
    except (KeyError, TypeError):
        raise SyncError("spring.io: the security page's data is not laid out as expected") from None
    out = {}
    for node in nodes:
        fields = (node or {}).get("fields") or {}
        slug = (fields.get("slug") or "").upper()
        if not slug.startswith("CVE-"):
            continue
        affected = fields.get("affected")
        try:
            affected = json.loads(affected) if isinstance(affected, str) and affected else affected or {}
        except ValueError:
            affected = {}
        modules = [a for a in (affected.get("artifacts") or []) if isinstance(a, str) and a.count(":") == 1]
        # A line without "introduced" is every version up to its last affected one.
        versions = [{"introduced": v.get("introduced") or "", "last_affected": v["last-affected"],
                     "fixes": [f["version"] for f in v.get("fixes") or [] if isinstance(f, dict) and f.get("version")]}
                    for v in affected.get("versions") or [] if isinstance(v, dict) and v.get("last-affected")]
        month, _, rest = (fields.get("publishedAt") or "").partition(" ")
        day, _, year = rest.partition(", ")
        published = f"{year}-{MONTHS[month]:02d}-{int(day):02d}" if month in MONTHS and day.isdigit() \
            and year.isdigit() else ""
        out[slug] = {"modules": modules, "versions": versions, "project": fields.get("project") or "",
                     "published": published}
    if not out:
        raise SyncError("spring.io: the security page's data lists no advisories")
    return out
