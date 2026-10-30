"""Command line: binwitness scan, binwitness crosscheck, binwitness db and binwitness mcp."""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from binwitness import __version__
from binwitness.crosscheck import CLASSES, crosscheck, load_other
from binwitness.localdb import (DATASETS, GROUPS, HASHES_REFRESH_DAYS, STALE_DAYS, LocalDb, SyncError,
                                default_db_dir, expand)
from binwitness.maven import CENTRAL
from binwitness.net import Net, default_cache_dir
from binwitness.output import render_summary, write_all
from binwitness.scan import Options, scan
from binwitness.vulns import SEVERITIES

DESCRIPTION = ("Evidence-backed software composition analysis for delivered binaries: jars, wars, container images "
               "and front-end builds.")
# What a --fail-on gate cannot vouch for: components it could not name, or could not look up.
UNCHECKED = ("jars_not_looked_up", "scripts_not_looked_up", "vulnerabilities_not_checked")


def _network_arguments(parser: argparse.ArgumentParser):
    group = parser.add_argument_group("network")
    group.add_argument("--offline", action="store_true",
                       help="no network: answer from local datasets and the response cache (what neither holds is "
                            "reported, not fetched)")
    group.add_argument("--max-age", type=float, default=12.0, metavar="HOURS",
                       help="refetch vulnerability data older than this (default 12)")
    group.add_argument("--cache-dir", type=Path, default=None,
                       help=f"response cache (default {default_cache_dir()}, or $BINWITNESS_CACHE)")
    group.add_argument("--workers", type=int, default=16, help="parallel lookups (default 16)")
    group.add_argument("--maven-mirror", metavar="URL",
                       help="fetch Maven Central files (checksums, POMs, jar directories) from this mirror of it; "
                            "hash search and deps.dev are unaffected")


def _lookup_arguments(parser: argparse.ArgumentParser):
    group = parser.add_argument_group("local datasets")
    group.add_argument("--lookup", choices=("auto", "local", "online"), default="auto",
                       help="auto: datasets synced with `binwitness db sync` first, online services for the rest "
                            "(default); local: never use the network, only local datasets and the response "
                            "cache (same as --offline); online: ignore local datasets (with --offline: replay "
                            "an earlier online scan from the cache)")
    _db_dir_argument(group)


def _db_dir_argument(parser):
    parser.add_argument("--db-dir", type=Path, default=None,
                        help=f"local datasets (default {default_db_dir()}, or $BINWITNESS_DB)")


def _net(args, offline: bool | None = None) -> Net:
    mirrors = {CENTRAL: args.maven_mirror.rstrip("/")} if args.maven_mirror else {}
    return Net(cache_dir=args.cache_dir or default_cache_dir(), offline=args.offline if offline is None else offline,
               max_age_hours=args.max_age, mirrors=mirrors)


def _minute(stamp: str | None) -> str:
    # Publishers state UTC with anything from no fraction to nanoseconds; minutes are enough to judge age.
    return f"{stamp[:10]} {stamp[11:16]} UTC" if stamp and len(stamp) >= 16 else "?"


def _hashes_detail(row: dict, hashes_every: float) -> str:
    """How the hash index is made up, so a user can tell what the next sync will download."""
    base = row.get("base_as_of") or row["data_as_of"]
    renewal = datetime.fromisoformat(base[:19]).replace(tzinfo=timezone.utc) + timedelta(days=hashes_every)
    if row.get("chunk") is None:
        additions = "not applied yet; the next sync applies them"
    else:
        additions = (f"up to #{row['chunk']} ({row.get('recent_records') or 0:,} records), checked "
                     f"{(row.get('checked') or '?')[:10]}")
    return f"base {base[:10]}, replaced after {renewal:%Y-%m-%d}; Maven Central additions {additions}"


def _database(args) -> int:
    db = LocalDb(args.db_dir)
    if args.action == "status":
        print(f"{db.directory}")
        rows = db.status()
        for row in rows:
            if row["installed"]:
                print(f"  {row['name']:13} {row['bytes'] / 2**20:8.1f} MB  {row['records'] or 0:>11,} records  "
                      f"data as of {_minute(row['data_as_of'])}  synced {_minute(row['synced'])}")
                if row["name"] == "maven-hashes":
                    print(f"  {'':13} {_hashes_detail(row, args.hashes_every)}")
                if row["name"] == "nvd" and not row["layout_current"]:
                    print(f"  {'':13} stored by an earlier version: the next sync downloads it again (about 235 MB)")
                if row["name"] == "fixes":
                    print(f"  {'':13} {row['commits'] or 0:,} commits read" + (
                        f"; {row['commits_not_read']:,} not fetched yet: sync fixes again" if row["commits_not_read"]
                        else ""))
            else:
                print(f"  {row['name']:13} not installed ({row['download']}): {row['description']}")
        groups = "; ".join(f"{group} = {' '.join(members)}" for group, members in GROUPS.items())
        print(f"groups: {groups}")
        stale = [row["name"] for row in rows if row["installed"] and
                 (datetime.now(timezone.utc) - datetime.fromisoformat(row["synced"])).days > STALE_DAYS]
        if stale:
            print(f"last synced more than {STALE_DAYS} days ago: {' '.join(stale)}; run `binwitness db sync`")
        if not any(row["installed"] for row in rows):
            print("nothing installed yet; `binwitness db sync java` (about 1 GB) covers most Java lookups")
        return 0
    try:
        names = expand(args.datasets) if args.datasets else db.installed()
    except ValueError as error:
        print(f"binwitness db: {error}", file=sys.stderr)
        return 2
    try:
        if args.action == "remove":
            db.remove(names)
            print(f"removed {', '.join(names)}")
            return 0
        if names:
            outcomes = db.sync(names, full=args.full, hashes_every=args.hashes_every,
                               log=lambda message: print(message, file=sys.stderr, flush=True))
    except SyncError as error:
        print(f"binwitness db: {error}", file=sys.stderr)
        return 1
    if not names:
        print("no dataset installed yet; name the ones to sync:", file=sys.stderr)
        for name, dataset in DATASETS.items():
            print(f"  {name:13} {dataset.size:30} {dataset.description}", file=sys.stderr)
        print(f"  or a group: {', '.join(GROUPS)}", file=sys.stderr)
        return 2
    for name, outcome in outcomes.items():
        print(f"{name}: {outcome}")
    return 1 if any(o.startswith("failed") for o in outcomes.values()) else 0


def _repositories(parser: argparse.ArgumentParser, urls: list[str]) -> tuple[str, ...]:
    repositories = tuple(dict.fromkeys(url.rstrip("/") for url in urls))
    if any(not url.startswith(("https://", "http://")) for url in repositories):
        parser.error("--maven-repo takes an http(s) URL")
    return repositories


def _serve(parser: argparse.ArgumentParser, args) -> int:
    from binwitness import mcp_server
    for root in args.root:
        if not root.is_dir():
            parser.error(f"--root {root} is not a directory")
    config = mcp_server.Config(
        lookup="local" if args.offline else args.lookup, roots=tuple(args.root),
        results=args.results or mcp_server.default_results_dir(), allow_class_search=args.allow_class_search,
        cache_dir=args.cache_dir, db_dir=args.db_dir, maven_mirror=args.maven_mirror,
        maven_repos=_repositories(parser, args.maven_repo), workers=args.workers, max_age=args.max_age)
    try:
        server = mcp_server.build_server(mcp_server.Service(config))
    except ImportError as error:
        if (error.name or "").split(".")[0] not in ("mcp", "pydantic", "anyio"):
            raise
        print('binwitness mcp needs the MCP SDK: pip install "binwitness[mcp]" (or, installed with pipx: '
              'pipx install --force "binwitness[mcp]")', file=sys.stderr)
        return 2
    server.run(transport="stdio")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("binwitness: interrupted", file=sys.stderr)
        # Lookups already sent hold their worker threads until they answer or time out, and the interpreter
        # waits for them before it exits. The cache is written atomically, so nothing is left half-written.
        if threading.active_count() > 1:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(130)
        return 130


def _output_directory(parser: argparse.ArgumentParser, path: Path):
    """Checked before the scan rather than after it: a large delivery takes many minutes to scan."""
    if path.exists() and not path.is_dir():
        parser.error(f"--out {path} is a file; give a directory for the result files")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        parser.error(f"cannot create --out {path}: {error}")
    if not os.access(path, os.W_OK):
        parser.error(f"cannot write to --out {path}")


def _main(argv: list[str] | None) -> int:
    parser = argparse.ArgumentParser(prog="binwitness", description=DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"binwitness {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("scan", help="identify components in delivered artifacts")
    run.add_argument("inputs", nargs="+", type=Path, help="files or directories (archives, images, builds)")
    run.add_argument("-o", "--out", type=Path, required=True, help="output directory")
    run.add_argument("--first-party-group", action="append", default=[], metavar="PREFIX",
                     help="Maven groupId prefix of your own code (repeatable)")
    run.add_argument("--first-party-jar", action="append", default=[], metavar="PREFIX",
                     help="jar file name prefix of your own code (repeatable)")
    run.add_argument("--first-party-npm", action="append", default=[], metavar="PREFIX",
                     help="npm package name prefix of your own code, e.g. @acme/ (repeatable)")
    run.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                     help="skip locations matching this glob (repeatable)")
    run.add_argument("--class-search", action="store_true",
                     help="identify rebuilt jars that carry no coordinates: search Maven Central for one class "
                          "name per unidentified jar and try coordinates its file name suggests, then compare "
                          "contents (sends that class name and those coordinates)")
    run.add_argument("--maven-repo", action="append", default=[], metavar="URL",
                     help="another Maven repository that publishes releases Maven Central does not have "
                          "(milestones, a vendor's own); checked after Central, in the order given (repeatable)")
    run.add_argument("--no-js", action="store_true", help="do not look up vendored JavaScript files")
    run.add_argument("--no-licenses", action="store_true", help="skip license resolution")
    run.add_argument("--no-vulns", action="store_true", help="skip vulnerability lookup")
    run.add_argument("--no-upgrades", action="store_true",
                     help="skip upgrade advice (which published version leaves the findings behind; reads each "
                          "vulnerable package's version list and all of its advisories)")
    run.add_argument("--unpacker", help="rar/7z extractor to use (unrar, 7z or bsdtar; default: first on PATH)")
    run.add_argument("--fail-on", choices=[s.lower() for s in SEVERITIES[:4]],
                     help="exit with status 3 if any vulnerability at or above this severity is found, or 4 if "
                          "none is but the scan could not check everything (failed or offline lookups) or "
                          "found nothing to check")
    _network_arguments(run)
    _lookup_arguments(run)

    check = commands.add_parser("crosscheck", help="classify another scanner's findings against a scan result")
    check.add_argument("result", type=Path, help="binwitness.json from a scan")
    check.add_argument("other", help="the other tool's findings: CSV (component,version,vulnerability) "
                                     "or CycloneDX JSON")
    check.add_argument("-o", "--out", type=Path, required=True, help="output JSON file")
    _network_arguments(check)

    database = commands.add_parser("db", help="local copies of public datasets: sync, status, remove")
    actions = database.add_subparsers(dest="action", required=True)
    choices = f"{', '.join(DATASETS)}, or a group ({', '.join(GROUPS)})"
    sync = actions.add_parser("sync", help="install datasets, or update installed ones (incremental where the "
                                           "publisher allows)")
    sync.add_argument("datasets", nargs="*", metavar="DATASET", help=f"{choices}; default: those installed")
    sync.add_argument("--full", action="store_true", help="download again in full instead of updating")
    sync.add_argument("--hashes-every", type=float, default=HASHES_REFRESH_DAYS, metavar="DAYS",
                      help=f"download the 1 GB base of the Maven Central hash index again when it is older than "
                           f"this (default {HASHES_REFRESH_DAYS}); every sync in between applies Central's weekly "
                           f"additions")
    _db_dir_argument(sync)
    status = actions.add_parser("status", help="installed datasets, their age and size")
    status.add_argument("--hashes-every", type=float, default=HASHES_REFRESH_DAYS, metavar="DAYS",
                        help="the value you give db sync, to show when the hash index base will be replaced")
    _db_dir_argument(status)
    remove = actions.add_parser("remove", help="delete installed datasets")
    remove.add_argument("datasets", nargs="+", metavar="DATASET", help=choices)
    _db_dir_argument(remove)

    serve = commands.add_parser("mcp", help="serve scans and their results to an AI assistant over the Model "
                                            "Context Protocol (stdio); needs the mcp extra",
                                description="Serve scans and their results to an AI assistant over the Model "
                                            "Context Protocol (stdio). --lookup is the most a scan may use; the "
                                            "assistant can ask for less.")
    serve.add_argument("--root", action="append", default=[], type=Path, metavar="DIR",
                       help="a directory whose files the assistant may scan (repeatable); without one it can only "
                            "read results opened by path")
    serve.add_argument("--results", type=Path, default=None, metavar="DIR",
                       help="where scans are written (default: binwitness/scans in the user data directory)")
    serve.add_argument("--allow-class-search", action="store_true",
                       help="let scans use --class-search, which sends class names to Maven Central")
    serve.add_argument("--maven-repo", action="append", default=[], metavar="URL",
                       help="another Maven repository for every scan (repeatable)")
    _network_arguments(serve)
    _lookup_arguments(serve)

    args = parser.parse_args(argv)
    if args.command == "db":
        return _database(args)
    if args.command == "mcp":
        return _serve(parser, args)
    if args.command == "scan":
        missing = [str(p) for p in args.inputs if not p.exists()]
        if missing:
            parser.error(f"not found: {', '.join(missing)}")
        if args.fail_on and args.no_vulns:
            parser.error("--fail-on needs the vulnerability lookup that --no-vulns turns off")
        repositories = _repositories(parser, args.maven_repo)
        _output_directory(parser, args.out)
        options = Options(first_party_groups=tuple(args.first_party_group),
                          first_party_jars=tuple(args.first_party_jar),
                          first_party_npm=tuple(args.first_party_npm), exclude=tuple(args.exclude),
                          scan_js=not args.no_js, licenses=not args.no_licenses,
                          vulnerabilities=not args.no_vulns, workers=args.workers, unpacker=args.unpacker,
                          class_search=args.class_search, maven_repos=repositories, upgrades=not args.no_upgrades,
                          lookup="local" if args.offline and args.lookup == "auto" else args.lookup)
        local = args.offline or args.lookup == "local"
        db = None if args.lookup == "online" else LocalDb.open(args.db_dir)
        # Candidates exist only locally; an online scan takes them from the datasets that are installed.
        result = scan(args.inputs, _net(args, offline=local), options, db=db,
                      candidates_db=LocalDb.open(args.db_dir) if args.lookup == "online" else None)
        for path in write_all(result, args.out):
            print(f"wrote {path}", file=sys.stderr)
        print(render_summary(result))
        if args.fail_on:
            threshold = SEVERITIES.index(args.fail_on.upper())
            if any(SEVERITIES.index(v["severity"]) <= threshold for v in result["vulnerabilities"].values()):
                return 3
            summary = result["summary"]
            unchecked = any(summary["incomplete"].get(k) for k in UNCHECKED)
            if unchecked or not (summary["components"]["total"] or summary["jars"]["distinct_files"]):
                print("binwitness: --fail-on: nothing at that severity was found, but the scan "
                      + ("could not check everything" if unchecked else "found nothing to check"), file=sys.stderr)
                return 4
        return 0

    if args.out.is_dir():
        parser.error(f"--out {args.out} is a directory; give the name of the JSON file to write")
    result = json.loads(args.result.read_text("utf-8"))
    report = crosscheck(result, load_other(args.other), _net(args), workers=min(args.workers, 4))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1), "utf-8")
    s = report["summary"]
    print(f"components identified at the same version by both: {s['components_in_both']}")
    print(f"findings in both {s['findings_in_both']}, only binwitness {s['only_ours']}, "
          f"only the other tool {s['only_theirs']}")
    among = s["only_theirs_among_candidates"]
    for name, count in s["only_theirs_by_class"].items():
        print(f"  {count:5d}  {name}: {CLASSES[name]}"
              + (f" ({among[name]} of them NVD candidates of this scan)" if among.get(name) else ""))
    if s["only_theirs"] and not s["candidates_checked"]:
        print("  (NVD candidates were not looked for in this scan)")
    if not s["github_token"]:
        print("note: no GitHub token (GITHUB_TOKEN or `gh auth login`); unauthenticated API allows 60 lookups/hour",
              file=sys.stderr)
    return 0
