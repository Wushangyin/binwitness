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
changes; a copy synced within a week is updated from the latter, an older one is downloaded again.
"""
from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import os
import posixpath
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
from collections.abc import Callable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
    import msvcrt

from binwitness import nvd
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
# Rows per SQL statement when looking up a list of ids: SQLite allows a few hundred parameters at most.
ID_BATCH = 500


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
                 sha256: str | None = None, progress: Callable[[int, int | None], None] | None = None):
        """Stream ``url`` into ``target``. A connection that drops resumes where it stopped; ``If-Range``
        makes the server send the whole file instead if it changed in the meantime. ``headers`` may be a
        function, called before every attempt, for credentials that expire during a long download."""
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
        if sha256:
            algorithm, _, expected = sha256.partition(":")
            digest = hashlib.sha256()
            with target.open("rb") as stream:
                while chunk := stream.read(1 << 20):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                target.unlink()
                raise SyncError(f"{url}: downloaded file does not match its {algorithm} digest")

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
                         **({"without_cpe": entry.get("without_cpe")} if name == "nvd" else {})})
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
                else:
                    entry, outcome = self._sync_maven_hashes(full, hashes_every, fetcher, log)
            except (SyncError, OSError, ValueError, KeyError, sqlite3.Error, zipfile.BadZipFile,
                    tarfile.TarError, EOFError, zlib.error, struct.error) as error:
                outcomes[name] = f"failed: {error}"
                continue
            self.state[name] = {**self.state.get(name, {}), **entry, "synced": _now()}
            self._write_state()
            outcomes[name] = outcome
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
        fetcher.download(url, archive_path, progress=self._progress(log, name))
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

    # ---- NVD ------------------------------------------------------------------------------------------

    def _sync_nvd(self, full, fetcher, log):
        entry = self.state.get("nvd", {}) if self.has("nvd") else {}
        if not full and entry and time.time() - _epoch(entry["data_as_of"]) < NVD_MODIFIED_DAYS * 86400:
            return self._nvd_update(entry, fetcher, log)
        building = self.path("nvd").with_name(self.path("nvd").name + ".building")
        building.unlink(missing_ok=True)
        newest, stored = "", 0
        with closing(sqlite3.connect(building)) as connection:
            connection.executescript(nvd.SCHEMA)
            for year in range(nvd.FIRST_YEAR, datetime.now(timezone.utc).year + 1):
                (feed_newest, feed_stored, _), _ = self._nvd_feed(connection, f"nvdcve-2.0-{year}", fetcher, log)
                newest, stored = max(newest, feed_newest), stored + feed_stored
            # Built after the bulk insert, as for OSV.
            connection.execute("CREATE INDEX cpes_product ON cpes(vendor, product)")
            connection.execute("CREATE INDEX cpes_id ON cpes(id)")
            connection.commit()
            entry = self._nvd_entry(connection, newest)
        self.close()
        os.replace(building, self.path("nvd"))
        return {**entry, "full_download": _now(), "modified_sha256": None}, f"downloaded {stored} records with a CPE"

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

    def _nvd_feed(self, connection, name, fetcher, log, meta=None, replace=False):
        """Load one feed: ((newest modification, records stored, records dropped first), its .meta). The feed
        is checked against the digest in the .meta while it is read. One that does not match (left by an
        earlier attempt, or regenerated in between) is downloaded once more."""
        target = self._scratch() / f"{name}.json.gz"
        for attempt in (1, 2):
            meta = meta or self._nvd_meta(name, fetcher)
            fetcher.download(f"{nvd.NVD_FEEDS}/{name}.json.gz", target, progress=self._progress(log, name))
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
                         progress=self._progress(log, "maven-hashes"))
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

    def __init__(self, stream):
        self.stream, self.buffer, self.offset = stream, b"", 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.buffer):
            self.buffer = self.buffer[self.offset:] + self.stream.read(max(size, 4 << 20))
            self.offset, end = 0, size
            if end > len(self.buffer):
                if self.buffer:
                    raise EOFError("Central index chunk ends inside a record")
                return b""
        data = self.buffer[self.offset:end]
        self.offset = end
        return data

    def number(self, form: str) -> int:
        data = self.take(struct.calcsize(form))
        if not data:
            raise EOFError("Central index chunk ends inside a record")
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
