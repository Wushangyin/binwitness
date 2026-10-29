"""npm packages from lockfiles (npm v1-v3, yarn classic and berry, pnpm) and installed node_modules."""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass


@dataclass
class NpmPackage:
    name: str
    version: str
    scope: str | None   # "runtime" | "dev" | "unknown"; None when the source does not say
    license: str | None
    source: str         # which kind of file stated it


def parse(filename: str, data: bytes) -> list[NpmPackage]:
    base = posixpath.basename(filename).lower()
    text = data.decode("utf-8", "replace")
    if base == "yarn.lock":
        return _yarn(text)
    if base == "pnpm-lock.yaml":
        return _pnpm(text)
    if base == "package.json":
        return _installed(text)
    return _package_lock(text)


def _license(value) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("type")
    if isinstance(value, list):
        names = [_license(v) for v in value]
        return " OR ".join(n for n in names if n) or None
    return None


def _usable(version) -> bool:
    # Links, git URLs and tarball paths have no registry version to look up.
    return isinstance(version, str) and re.match(r"^\d+\.\d+", version) is not None


def _package_lock(text: str) -> list[NpmPackage]:
    try:
        lock = json.loads(text)
    except ValueError:
        return []
    out = []
    packages = lock.get("packages")
    if isinstance(packages, dict) and packages:
        for path, entry in packages.items():
            if not path or entry.get("link") or "node_modules/" not in path:
                continue
            name = entry.get("name") or path.rsplit("node_modules/", 1)[1]
            if _usable(entry.get("version")):
                out.append(NpmPackage(name, entry["version"], "dev" if entry.get("dev") else "runtime",
                                      _license(entry.get("license")), f"package-lock v{lock.get('lockfileVersion')}"))
        return out

    def walk(dependencies):
        for name, entry in (dependencies or {}).items():
            if _usable(entry.get("version")):
                out.append(NpmPackage(name, entry["version"], "dev" if entry.get("dev") else "runtime", None,
                                      "package-lock v1"))
            walk(entry.get("dependencies"))

    walk(lock.get("dependencies"))
    return out


def _spec_name(spec: str) -> str:
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def _yarn(text: str) -> list[NpmPackage]:
    """yarn classic (v1) and berry (v2+): a line of specs, then the entry's indented fields."""
    entries: list[tuple[str, dict[str, str]]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            entries.append((line.rstrip()[:-1], {}))
            continue
        # Two spaces exactly: deeper lines belong to the entry's dependency lists.
        field = re.match(r'^ {2}(\w+):?\s+"?([^"\s]+)"?\s*$', line)
        if field and entries:
            entries[-1][1].setdefault(field.group(1), field.group(2))
    out = []
    for key, fields in entries:
        # Berry marks workspace and patch entries with a protocol other than npm.
        if key.strip().strip('"') == "__metadata" or re.search(r"@(workspace|link|portal|file|patch):", key):
            continue
        name = _yarn_name([s.strip().strip('"') for s in key.split(",")], fields.get("resolution"))
        if name and _usable(fields.get("version")):
            out.append(NpmPackage(name, fields["version"], "unknown", None, "yarn.lock"))
    return out


def _yarn_name(specs: list[str], resolution: str | None) -> str | None:
    """The registry name an entry installs. An alias (``"eslint-v7@npm:eslint@^7.7.0"``) installs the package
    after ``npm:``; its own name is only a directory name, and squatters have published under such names."""
    if resolution:
        match = re.match(r"^(@?[^@]+)@npm:", resolution)
        return match.group(1) if match else None
    for spec in specs:
        target = spec.split("@npm:", 1)[1] if "@npm:" in spec else ""
        # "name@npm:^1.0" is berry's plain form; only "alias@npm:real@^1.0" names another package.
        if target.find("@", 1) > 0:
            return _spec_name(target)
    return _spec_name(specs[0])


def _pnpm(text: str) -> list[NpmPackage]:
    out = []
    in_packages = False
    current = None
    for line in text.splitlines():
        # pnpm separates entries with blank lines; only a top-level key ends the section.
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_packages = line.rstrip() == "packages:"
            current = None
            continue
        if not in_packages:
            continue
        key = re.match(r"^  (\S.*):\s*$", line)
        if key:
            current = _pnpm_key(key.group(1))
            if current:
                out.append(NpmPackage(*current, "unknown", None, "pnpm-lock.yaml"))
            continue
        if current and re.match(r"^    dev:\s*true\s*$", line):
            out[-1].scope = "dev"
        elif current and re.match(r"^    dev:\s*false\s*$", line):
            out[-1].scope = "runtime"
    return out


def _pnpm_key(key: str) -> tuple[str, str] | None:
    key = key.strip().strip("'\"").lstrip("/")
    key = re.sub(r"\(.*$", "", key)          # v6/v9 peer suffix: name@1.0.0(react@18.0.0)
    if "@" in key[1:]:
        name, version = key.rsplit("@", 1)  # v6/v9: name@1.0.0
    elif "/" in key:
        name, version = key.rsplit("/", 1)  # v5: name/1.0.0_peer
        version = version.split("_", 1)[0]
    else:
        return None
    return (name, version) if _usable(version) else None


def _installed(text: str) -> list[NpmPackage]:
    try:
        manifest = json.loads(text)
    except ValueError:
        return []
    if not isinstance(manifest, dict) or not manifest.get("name") or not _usable(manifest.get("version")):
        return []
    found = _license(manifest.get("license")) or _license(manifest.get("licenses"))
    # An installed copy says nothing about whether the package ships; a lockfile beside it does.
    return [NpmPackage(manifest["name"], manifest["version"], None, found, "node_modules package.json")]
