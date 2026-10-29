"""Command line: ``binwitness scan``, ``binwitness crosscheck`` and ``binwitness db``."""
from __future__ import annotations

import argparse
import json
import sys
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="binwitness", description=__doc__)
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
                          "name per unidentified jar, then compare contents (sends that class name)")
    run.add_argument("--no-js", action="store_true", help="do not look up vendored JavaScript files")
    run.add_argument("--no-licenses", action="store_true", help="skip license resolution")
    run.add_argument("--no-vulns", action="store_true", help="skip vulnerability lookup")
    run.add_argument("--unpacker", help="rar/7z extractor to use (unrar, 7z or bsdtar; default: first on PATH)")
    run.add_argument("--fail-on", choices=[s.lower() for s in SEVERITIES[:4]],
                     help="exit with status 3 if any vulnerability at or above this severity is found")
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

    args = parser.parse_args(argv)
    if args.command == "db":
        return _database(args)
    if args.command == "scan":
        missing = [str(p) for p in args.inputs if not p.exists()]
        if missing:
            parser.error(f"not found: {', '.join(missing)}")
        options = Options(first_party_groups=tuple(args.first_party_group),
                          first_party_jars=tuple(args.first_party_jar),
                          first_party_npm=tuple(args.first_party_npm), exclude=tuple(args.exclude),
                          scan_js=not args.no_js, licenses=not args.no_licenses,
                          vulnerabilities=not args.no_vulns, workers=args.workers, unpacker=args.unpacker,
                          class_search=args.class_search)
        local = args.offline or args.lookup == "local"
        db = None if args.lookup == "online" else LocalDb.open(args.db_dir)
        result = scan(args.inputs, _net(args, offline=local), options, db=db)
        for path in write_all(result, args.out):
            print(f"wrote {path}", file=sys.stderr)
        print(render_summary(result))
        if args.fail_on:
            threshold = SEVERITIES.index(args.fail_on.upper())
            if any(SEVERITIES.index(v["severity"]) <= threshold for v in result["vulnerabilities"].values()):
                return 3
        return 0

    result = json.loads(args.result.read_text("utf-8"))
    report = crosscheck(result, load_other(args.other), _net(args), workers=min(args.workers, 4))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1), "utf-8")
    s = report["summary"]
    print(f"components identified at the same version by both: {s['components_in_both']}")
    print(f"findings in both {s['findings_in_both']}, only binwitness {s['only_ours']}, "
          f"only the other tool {s['only_theirs']}")
    for name, count in s["only_theirs_by_class"].items():
        print(f"  {count:5d}  {name}: {CLASSES[name]}")
    if not s["github_token"]:
        print("note: no GitHub token (GITHUB_TOKEN or `gh auth login`); unauthenticated API allows 60 lookups/hour",
              file=sys.stderr)
    return 0
