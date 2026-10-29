"""Walk delivered artifacts and yield the files that carry composition evidence.

Inputs can be directories, archives (zip/jar/war/ear, tar and compressed tar, rar/7z through an external
tool) and ``docker save`` image tarballs, nested to any depth. Locations are written Java-URL style,
``outer.tar!/app/lib/app.jar!/BOOT-INF/lib/dep.jar``, rooted at the input's own name so results never
contain the scanning machine's absolute paths.
"""
from __future__ import annotations

import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

JAR_SUFFIXES = (".jar",)
ZIP_SUFFIXES = (".zip", ".war", ".ear", ".sar")
TAR_SUFFIXES = (".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".txz")
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", ".package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
SKIP_DIRS = {".git", ".svn", ".hg", "__MACOSX"}
# Vendored scripts below this size are almost never a library worth a registry lookup.
JS_MIN_SIZE = 1024
JS_MAX_SIZE = 16 * 1024 * 1024
ENTRY_MAX_SIZE = 4 * 1024 ** 3
JDK_JARS = {"jrt-fs.jar", "rt.jar", "tools.jar", "charsets.jar", "jce.jar", "jsse.jar", "resources.jar",
            "dnsns.jar", "localedata.jar", "nashorn.jar", "sunec.jar", "sunjce_provider.jar", "sunpkcs11.jar",
            "zipfs.jar", "cldrdata.jar", "jaccess.jar", "jfr.jar", "management-agent.jar"}


@dataclass
class Item:
    kind: str          # "jar" | "lockfile" | "npm-package" | "js"
    location: str
    data: bytes


@dataclass
class Walker:
    scan_js: bool = True
    exclude: tuple[str, ...] = ()
    max_depth: int = 8
    unpacker: str | None = None
    warnings: list[str] = field(default_factory=list)
    skipped_runtime_jars: int = 0

    def walk(self, path: Path) -> Iterator[Item]:
        path = Path(path)
        label = path.name or str(path)
        if path.is_dir():
            yield from self._directory(path, label, 0)
        else:
            yield from self._file(label, path.name, lambda: path, 0, on_disk=True)

    # ---- containers -----------------------------------------------------------------------------------

    def _directory(self, root: Path, label: str, depth: int) -> Iterator[Item]:
        for current, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                full = Path(current) / name
                if full.is_symlink():
                    continue
                rel = full.relative_to(root).as_posix()
                yield from self._file(f"{label}/{rel}", rel, lambda full=full: full, depth, on_disk=True)

    def _file(self, location: str, inner_name: str, opener: Callable, depth: int,
              on_disk: bool = False) -> Iterator[Item]:
        """``opener`` returns a Path when ``on_disk`` else the entry's bytes; it is only called when needed."""
        if any(fnmatch(location, pattern) for pattern in self.exclude):
            return
        # macOS archivers add __MACOSX/ and ._name AppleDouble entries: metadata, never content.
        if "__MACOSX/" in inner_name or posixpath.basename(inner_name).startswith("._"):
            return
        lower = posixpath.basename(inner_name).lower()
        kind = self._kind(inner_name, lower)
        if kind is None:
            return
        if kind == "runtime-jar":
            self.skipped_runtime_jars += 1
            return

        def blob() -> bytes:
            source = opener()
            return source.read_bytes() if on_disk else source

        if kind in ("lockfile", "npm-package", "js"):
            data = blob()
            if kind == "js" and not JS_MIN_SIZE <= len(data) <= JS_MAX_SIZE:
                return
            yield Item(kind, location, data)
            return
        if depth >= self.max_depth:
            self.warnings.append(f"{location}: nested deeper than {self.max_depth} archives, not opened")
            return
        try:
            if kind == "jar":
                data = blob()
                yield Item("jar", location, data)
                yield from self._zip(io.BytesIO(data), location, depth + 1, inside_jar=True)
            elif kind == "zip":
                source = opener()
                yield from self._zip(source if on_disk else io.BytesIO(source), location, depth + 1)
            elif kind == "tar":
                source = opener()
                yield from self._tar(source if on_disk else io.BytesIO(source), location, depth + 1)
            elif kind == "external":
                yield from self._external(opener(), location, depth + 1, on_disk)
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError) as error:
            self.warnings.append(f"{location}: cannot open ({error.__class__.__name__}: {error})")

    def _kind(self, inner_name: str, lower: str) -> str | None:
        parts = inner_name.split("/")
        if lower in LOCKFILES:
            return "lockfile"
        if lower == "package.json" and _is_node_module_manifest(parts):
            return "npm-package"
        if lower.endswith(JAR_SUFFIXES):
            return "runtime-jar" if _is_java_runtime(inner_name) else "jar"
        if lower.endswith((".rar", ".7z")):
            return "external"
        if lower.endswith(ZIP_SUFFIXES):
            return "zip"
        if lower.endswith(TAR_SUFFIXES):
            return "tar"
        if (self.scan_js and lower.endswith(".js") and "node_modules" not in parts
                and not lower.endswith((".map.js", ".d.js"))):
            return "js"
        return None

    def _zip(self, source, location: str, depth: int, inside_jar: bool = False) -> Iterator[Item]:
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.file_size > ENTRY_MAX_SIZE:
                    self.warnings.append(f"{location}!/{info.filename}: larger than {ENTRY_MAX_SIZE} bytes, skipped")
                    continue
                name = info.filename
                # A jar's own lockfiles or package.json (webjars) describe the jar, which is identified itself.
                if inside_jar and not name.lower().endswith(JAR_SUFFIXES + (".js",)):
                    continue
                yield from self._file(f"{location}!/{name}", name,
                                      lambda info=info: archive.read(info), depth)

    def _tar(self, source, location: str, depth: int) -> Iterator[Item]:
        opened = tarfile.open(source, mode="r:*") if isinstance(source, Path) else tarfile.open(
            fileobj=source, mode="r:*")
        with opened as archive:
            members = archive.getmembers()
            manifest = next((m for m in members if _clean(m.name) == "manifest.json" and m.isfile()), None)
            if manifest is not None:
                images = _image_manifest(archive, manifest, members)
                if images:
                    for tag, layers in images:
                        label = f"{location}!/<{tag}>"
                        if not any(fnmatch(label, pattern) for pattern in self.exclude):
                            yield from self._image(archive, layers, label, depth)
                    return
            for member in members:
                if member.isfile() or member.islnk():
                    yield from self._file(f"{location}!/{_clean(member.name)}", _clean(member.name),
                                          lambda m=member: _read_member(archive, m), depth)

    def _image(self, archive: tarfile.TarFile, layers: list[str], location: str, depth: int) -> Iterator[Item]:
        """Apply the layers in order (whiteouts included) and walk only the files present in the final image."""
        final: dict[str, int] = {}
        for index, layer in enumerate(layers):
            with _open_layer(archive, layer) as layer_tar:
                for member in layer_tar:
                    path = _clean(member.name)
                    head, base = posixpath.split(path)
                    if base == ".wh..wh..opq":
                        prefix = head + "/" if head else ""
                        for existing in [p for p in final if p.startswith(prefix)]:
                            del final[existing]
                    elif base.startswith(".wh."):
                        gone = posixpath.join(head, base[4:])
                        for existing in [p for p in final if p == gone or p.startswith(gone + "/")]:
                            del final[existing]
                    elif member.isfile() or member.islnk():
                        if self._kind(path, base.lower()) is not None:
                            final[path] = index
                    elif not member.isdir():
                        final.pop(path, None)
        for index, layer in enumerate(layers):
            wanted = {p for p, i in final.items() if i == index}
            if not wanted:
                continue
            with _open_layer(archive, layer) as layer_tar:
                for member in layer_tar:
                    path = _clean(member.name)
                    if path in wanted:
                        yield from self._file(f"{location}/{path}", path,
                                              lambda m=member, t=layer_tar: _read_member(t, m), depth)

    def _external(self, source, location: str, depth: int, on_disk: bool) -> Iterator[Item]:
        tool = self.unpacker or next((t for t in ("unrar", "7zz", "7z", "bsdtar") if shutil.which(t)), None)
        if tool is None:
            self.warnings.append(f"{location}: no rar/7z extractor found (install unrar, 7z or bsdtar), skipped")
            return
        with tempfile.TemporaryDirectory(prefix="binwitness-") as work:
            archive_path = Path(source) if on_disk else Path(work) / "archive.bin"
            if not on_disk:
                archive_path.write_bytes(source)
            out = Path(work) / "out"
            out.mkdir()
            name = Path(tool).name
            if name.startswith("unrar"):
                command = [tool, "x", "-idq", "-o+", str(archive_path), str(out) + "/"]
            elif name.startswith("7z"):
                command = [tool, "x", "-y", "-bd", f"-o{out}", str(archive_path)]
            else:
                command = [tool, "-xf", str(archive_path), "-C", str(out)]
            done = subprocess.run(command, capture_output=True)
            if done.returncode != 0:
                self.warnings.append(f"{location}: {name} failed ({done.stderr.decode(errors='replace')[:200]})")
            for current, dirs, files in os.walk(out):
                dirs.sort()
                for file_name in sorted(files):
                    full = Path(current) / file_name
                    if full.is_symlink():
                        continue
                    rel = full.relative_to(out).as_posix()
                    yield from self._file(f"{location}!/{rel}", rel, lambda full=full: full, depth, on_disk=True)


def _clean(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    handle = archive.extractfile(member)
    return handle.read() if handle else b""


def _open_layer(archive: tarfile.TarFile, layer: str) -> tarfile.TarFile:
    member = archive.getmember(layer)
    if member.issym():
        member = archive.getmember(posixpath.normpath(posixpath.join(posixpath.dirname(layer), member.linkname)))
    return tarfile.open(fileobj=archive.extractfile(member), mode="r:*")


def _image_manifest(archive: tarfile.TarFile, manifest: tarfile.TarInfo, members) -> list[tuple[str, list[str]]]:
    try:
        entries = json.loads(_read_member(archive, manifest))
    except ValueError:
        return []
    if not isinstance(entries, list):
        return []
    names = {m.name for m in members}
    images = []
    for entry in entries:
        layers = entry.get("Layers") if isinstance(entry, dict) else None
        if not layers or not all(layer in names for layer in layers):
            return []
        tags = entry.get("RepoTags") or []
        tag = tags[0] if tags else (entry.get("Config") or "image").rsplit("/", 1)[-1][:19]
        images.append((tag, layers))
    return images


def _is_node_module_manifest(parts: list[str]) -> bool:
    """``node_modules/<name>/package.json`` or ``node_modules/@scope/<name>/package.json`` only: packages
    carry extra package.json files deeper down (``"type": "module"`` markers) that are not packages."""
    if len(parts) >= 3 and parts[-3] == "node_modules":
        return True
    return len(parts) >= 4 and parts[-4] == "node_modules" and parts[-3].startswith("@")


def _is_java_runtime(path: str) -> bool:
    """Jars that belong to a JDK/JRE installation inside an image or bundle, not to the application."""
    lowered = "/" + path.lower()
    if any(marker in lowered for marker in ("/jre/lib/", "/jvm/", "/jmods/")):
        return True
    return (lowered.rsplit("/", 1)[-1] in JDK_JARS
            and re.search(r"/[^/]*(jdk|java|jre)[^/]*/lib/(ext/)?[^/]+$", lowered) is not None)
