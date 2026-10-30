"""The classes a fix changed: the GitHub commits an NVD record cites, read for the source files they change.

A record's text names the product, and often the feature, but rarely the module the flaw is in; the commit that
fixed it changes that module's code. A candidate whose fix changed classes that the component's jar does not hold
is flagged: the flaw may be in another module of the project. Nothing is left out for it. A class can be missing
because it had another name in an older version, and a commit cited as the fix is not always the fix itself.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

COMMIT = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commits?/([0-9a-fA-F]{7,40})(?![0-9a-fA-F])")
GITHUB = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
# github.com paths that are not repositories.
NOT_OWNERS = {"advisories", "orgs", "users", "topics", "marketplace", "sponsors", "settings", "features", "about"}
# Maven and Gradle keep main code in src/main/<directory>: java, or a build variant's own (jdk1.4 at Bouncy Castle).
MAIN_SOURCE = re.compile(r"(?:^|/)src/main/([^/]+)/(.+)\.java$")
# A diff larger than this rewrites a tree (a merge, a reformat) rather than fixes a flaw.
MAX_DIFF_BYTES = 16 << 20
DIFF_FILE = b"diff --git a/"


def commits_cited(references: Iterable[str]) -> list[tuple[str, str]]:
    """(repository, sha) of each GitHub commit among a record's references, repository as ``owner/name``."""
    found = {}
    for url in references:
        match = COMMIT.match(url)
        if match and match.group(1).lower() not in NOT_OWNERS:
            found.setdefault((f"{match.group(1)}/{match.group(2)}".lower(), match.group(3).lower()), None)
    return list(found)


def repositories_cited(references: Iterable[str]) -> set[str]:
    """The GitHub repositories a record refers to, by any page of them."""
    out = set()
    for url in references:
        match = GITHUB.match(url)
        if match and match.group(1).lower() not in NOT_OWNERS:
            out.add(f"{match.group(1)}/{match.group(2)}".lower().removesuffix(".git"))
    return out


def commit_url(key: str) -> str:
    repository, _, sha = key.partition("@")
    return f"https://github.com/{repository}/commit/{sha}"


def read_diff(lines: Iterable[bytes], limit: int = MAX_DIFF_BYTES) -> dict:
    """What a commit's diff changes: its main-code classes with how each changed (modified, added, deleted,
    renamed: the old path), and how many other files. ``{"unread": "too large"}`` past ``limit`` bytes."""
    files, current, size = [], None, 0
    for line in lines:
        size += len(line)
        if size > limit:
            return {"unread": "too large"}
        if line.startswith(DIFF_FILE):
            if current:
                files.append(current)
            old, _, _ = line[len(DIFF_FILE):].rstrip(b"\r\n").decode("utf-8", "replace").partition(" b/")
            current = ["modified", old]
        elif current is None:
            continue
        elif line.startswith(b"new file mode"):
            current[0] = "added"
        elif line.startswith(b"deleted file mode"):
            current[0] = "deleted"
        elif line.startswith(b"rename from "):
            current = ["renamed", line[len(b"rename from "):].rstrip(b"\r\n").decode("utf-8", "replace")]
    if current:
        files.append(current)
    main, java_elsewhere, other = [], 0, 0
    for change, path in files:
        source = MAIN_SOURCE.search(path)
        if source:
            main.append([change, source.group(1), source.group(2).replace("/", ".")])
        elif path.endswith(".java"):
            java_elsewhere += 1
        else:
            other += 1
    return {"main": sorted(main), "java_elsewhere": java_elsewhere, "other": other}


def fix_of(entry: dict | None, commits: dict) -> dict | None:
    """What the fix of a record changed, from its entry in the dataset and the commits read: None when the record
    cites no commit. The classes come from the commits NVD tagged as the patch when it tagged any; from the others
    otherwise (``classes_from`` tells which), since a record may also cite the commit that brought the flaw in, or
    a test. ``classes`` are those the fix modified, deleted or renamed (by their old name): an affected version
    holds them. Classes it added are listed apart."""
    if not entry or not (entry.get("commits") or entry.get("elsewhere")):
        return None
    tagged = entry.get("patch")
    own = entry.get("commits") or []
    used = [k for k in own if k in tagged] if tagged else own
    cited, changed, added, variants = [], set(), set(), set()
    for key in own:
        read = commits.get(key)
        state = "not read" if read is None else read.get("unread") or (
            "main classes" if read["main"] else "no main-code class")
        cited.append({"url": commit_url(key), "patch_tag": None if tagged is None else key in tagged, "read": state})
        if key not in used:
            continue
        for change, variant, name in (read or {}).get("main") or []:
            variants.add(variant)
            (added if change == "added" else changed).add(name)
    source = "patch-tagged commits" if tagged else "commits not tagged as the patch" if tagged is not None \
        else "commits, tags not known"
    return {"commits": cited, "elsewhere": list(entry.get("elsewhere") or []), "classes": sorted(changed),
            "classes_added": sorted(added - changed), "source_directories": sorted(variants),
            "classes_from": source if changed or added else None}


def held(classes: list[str], entries: set[str] | None) -> list[str] | None:
    """The classes a jar holds, by their class files (in a multi-release jar's version folders, or relocated, too);
    None when its entries are unknown."""
    if entries is None:
        return None
    paths = {name: name.replace(".", "/") + ".class" for name in classes}
    return [name for name, path in paths.items() if any(e == path or e.endswith("/" + path) for e in entries)]
