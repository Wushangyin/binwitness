"""Walk delivered artifacts and yield the files that carry composition evidence.

Inputs can be directories, archives (zip/jar/war/ear and the other zip-based Java packages, tar and compressed
tar, rar/7z through an external tool) and container images (``docker save`` tarballs and OCI image layouts,
packed or unpacked), nested to any depth. A file whose name does not say what it is is recognised by its
content. Locations are written Java-URL style, ``outer.tar!/app/lib/app.jar!/BOOT-INF/lib/dep.jar``, rooted at
the input's own name so results never contain the scanning machine's absolute paths.
"""
from __future__ import annotations

import contextlib
import io
import json
import lzma
import os
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import BinaryIO

# Zip-based packages that a library or plugin is published as (Jenkins plugins, Android and NiFi archives,
# Karaf features): each is identified as a whole, as a jar is, and the jars inside it as well.
JAR_SUFFIXES = (".jar", ".hpi", ".jpi", ".aar", ".nar", ".kar")
ZIP_SUFFIXES = (".zip", ".war", ".ear", ".sar", ".esa", ".eba")
TAR_SUFFIXES = (".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", ".package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
SKIP_DIRS = {".git", ".svn", ".hg", "__MACOSX"}
# Files with these extensions never hold anything this tool reads, so their content is not sniffed. Office
# documents, wheels and browser extensions are zips too, but carry no Java or npm components.
NOT_ARCHIVES = frozenset("""
    class java kt kts scala groovy gradle py pyc pyo rb go rs c h cc cpp hpp cs php pl pm lua swift ts tsx jsx
    mjs cjs vue svelte json json5 map md markdown rst txt text log csv tsv xml xsd xsl xslt dtd wsdl tld html htm
    xhtml jsp jspf ftl vm css scss sass less styl properties yml yaml toml ini cfg conf config env sql sh bash
    zsh bat cmd ps1 mf sf rsa dsa ec pem crt cer der key p12 pfx jks keystore truststore csr pub asc sig lock
    gitignore gitattributes npmignore editorconfig license notice png jpg jpeg gif bmp ico svg webp tif tiff psd
    mp3 mp4 wav ogg webm avi mov flv woff woff2 ttf otf eot pdf so dll dylib exe o a lib obj node wasm docx xlsx
    pptx doc xls ppt odt ods odp epub apk ipa xpi crx vsix nupkg whl egg jmod deb rpm dmg iso msi cab
""".split())
# Vendored scripts below this size are almost never a library worth a registry lookup.
JS_MIN_SIZE = 1024
JS_MAX_SIZE = 16 * 1024 * 1024
MANIFEST_MAX_SIZE = 256 * 1024 ** 2
ENTRY_MAX_SIZE = 4 * 1024 ** 3
# Entries larger than this are copied to a temporary file and read from there, so that memory does not grow
# with the size of what is delivered (a nested fat jar, a tarball inside a zip).
SPOOL_SIZE = 16 * 1024 ** 2
# Jars and archives are compressed already; a large entry that expands a hundredfold is a decompression bomb.
BOMB_RATIO = 100
HEAD_SIZE = 4096
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
JDK_JARS = {"jrt-fs.jar", "rt.jar", "tools.jar", "charsets.jar", "jce.jar", "jsse.jar", "resources.jar",
            "dnsns.jar", "localedata.jar", "nashorn.jar", "sunec.jar", "sunjce_provider.jar", "sunpkcs11.jar",
            "zipfs.jar", "cldrdata.jar", "jaccess.jar", "jfr.jar", "management-agent.jar"}
# A JDK or JRE installation has a ``release`` file next to one of these, whatever directory it is in.
JAVA_HOME_MARKERS = ("bin/java", "bin/java.exe", "lib/modules", "lib/rt.jar", "jre/lib/rt.jar")


@dataclass
class Item:
    kind: str          # "jar" | "lockfile" | "npm-package" | "js"
    location: str
    # The content, or for jars the path of a file holding it: a file on disk, or an entry too large to keep
    # in memory, valid until the walk moves on to the next item.
    source: bytes | Path

    def read(self) -> bytes:
        return self.source if isinstance(self.source, bytes) else self.source.read_bytes()


@dataclass
class _Entry:
    """A file inside an input, read only as far as needed."""
    size: int | None
    open: Callable[[], BinaryIO]
    path: Path | None = None        # set when the file is on disk
    compressed: int | None = None   # stored size of a zip entry

    def head(self, count: int = HEAD_SIZE) -> bytes:
        with self.open() as handle:
            return handle.read(count)

    def read(self) -> bytes:
        with self.open() as handle:
            return handle.read()


class _Unsupported(Exception):
    pass


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
            yield from self._directory(path, label + "/", 0, follow_links=True)
        elif path.is_file():
            yield from self._file(label, path.name, _disk_entry(path), 0)
        else:
            self.warnings.append(f"{label}: not found or not a regular file, skipped")

    # ---- containers -----------------------------------------------------------------------------------

    def _directory(self, root: Path, prefix: str, depth: int, follow_links: bool) -> Iterator[Item]:
        """``follow_links``: true for what the user named, false for what an archive unpacked, whose links
        could point anywhere on the scanning machine."""
        visited = set()
        homes: list[str] = []
        for current, dirs, files in os.walk(root, followlinks=follow_links):
            here = Path(current)
            relative = here.relative_to(root).as_posix()
            relative = "" if relative == "." else relative + "/"
            if follow_links:
                # A link back up the tree, or two links to one directory: walk it once.
                status = here.stat()
                if (status.st_dev, status.st_ino) in visited:
                    dirs[:] = []
                    continue
                visited.add((status.st_dev, status.st_ino))
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            images = self._image_list(lambda name: _read_small(here / name), lambda name: (here / name).is_file(),
                                      (prefix + relative).rstrip("/")) if _may_be_image(files) else None
            if images is not None:
                dirs[:] = []
                for tag, layers in images:
                    label = f"{prefix}{relative}<{tag}>"
                    if not any(fnmatch(label, pattern) for pattern in self.exclude):
                        yield from self._image(lambda layer: _open_layer_file(here / layer), layers, label, depth)
                continue
            if "release" in files and any((here / marker).is_file() for marker in JAVA_HOME_MARKERS):
                homes.append(relative)
            for name in sorted(files):
                full = here / name
                rel = relative + name
                if full.is_symlink():
                    if not follow_links:
                        self.warnings.append(f"{prefix}{rel}: symbolic link inside an archive, not followed")
                        continue
                    if not full.exists():
                        self.warnings.append(f"{prefix}{rel}: broken symbolic link, skipped")
                        continue
                if not full.is_file():
                    continue
                yield from self._file(prefix + rel, rel, _disk_entry(full), depth, tuple(homes))

    def _file(self, location: str, inner_name: str, entry: _Entry, depth: int,
              homes: tuple[str, ...] = ()) -> Iterator[Item]:
        if any(fnmatch(location, pattern) for pattern in self.exclude):
            return
        # macOS archivers add __MACOSX/ and ._name AppleDouble entries: metadata, never content.
        if "__MACOSX/" in inner_name or posixpath.basename(inner_name).startswith("._"):
            return
        kind = self._kind(inner_name, posixpath.basename(inner_name).lower(), homes)
        if kind is None:
            return
        if kind == "runtime-jar":
            self.skipped_runtime_jars += 1
            return
        try:
            if kind in ("sniff", "rar"):
                kind = self._sniffed_kind(entry, kind, location)
                if kind is None:
                    return
            if kind in ("lockfile", "npm-package", "js"):
                limit = JS_MAX_SIZE if kind == "js" else MANIFEST_MAX_SIZE
                if entry.size is not None and entry.size > limit:
                    if kind != "js":
                        self.warnings.append(f"{location}: larger than {limit} bytes, skipped")
                    return
                if self._bomb(entry, location):
                    return
                data = entry.read()
                if kind == "js" and not JS_MIN_SIZE <= len(data) <= JS_MAX_SIZE:
                    return
                yield Item(kind, location, data)
                return
            if depth >= self.max_depth:
                self.warnings.append(f"{location}: nested deeper than {self.max_depth} archives, not opened")
                return
            if entry.path is None and entry.size is not None and entry.size > ENTRY_MAX_SIZE:
                self.warnings.append(f"{location}: larger than {ENTRY_MAX_SIZE} bytes, skipped")
                return
            if self._bomb(entry, location):
                return
            if kind == "tar" and entry.head(4) == ZSTD_MAGIC:
                raise _Unsupported("zstd compression is not supported")
            with _materialized(entry) as source:
                if kind == "zip-or-jar":
                    kind = "jar" if _holds_classes(source) else "zip"
                if kind == "jar":
                    yield Item("jar", location, source)
                    yield from self._zip(source, location, depth + 1, inside_jar=True)
                elif kind == "zip":
                    yield from self._zip(source, location, depth + 1)
                elif kind == "tar":
                    yield from self._tar(source, location, depth + 1)
                elif kind == "external":
                    yield from self._external(source, location, depth + 1)
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, RuntimeError,
                NotImplementedError, zlib.error, lzma.LZMAError, _Unsupported) as error:
            self.warnings.append(f"{location}: cannot open ({error.__class__.__name__}: {error})")

    def _kind(self, inner_name: str, lower: str, homes: tuple[str, ...] = ()) -> str | None:
        parts = inner_name.split("/")
        if lower in LOCKFILES:
            return "lockfile" if _is_project_lockfile(parts) else None
        if lower == "package.json":
            return "npm-package" if _is_node_module_manifest(parts) else None
        if lower.endswith(JAR_SUFFIXES):
            return "runtime-jar" if _is_java_runtime(inner_name) or inner_name.startswith(homes) else "jar"
        if lower.endswith(".rar"):
            # RAR archives and Java EE resource adapters share the extension; only the content tells them apart.
            return "rar"
        if lower.endswith(".7z"):
            return "external"
        if lower.endswith(ZIP_SUFFIXES):
            return "zip"
        if lower.endswith(TAR_SUFFIXES):
            return "tar"
        if lower.endswith(".js"):
            return ("js" if self.scan_js and "node_modules" not in parts
                    and not lower.endswith((".map.js", ".d.js")) else None)
        extension = posixpath.splitext(lower)[1][1:]
        # Shared libraries (libc.so.6) and manual pages carry numbered extensions.
        if extension in NOT_ARCHIVES or extension.isdigit():
            return None
        # A JDK keeps zips of its own under other names (lib/ct.sym, the API signatures javac reads).
        if _is_java_runtime(inner_name) or inner_name.startswith(homes):
            return None
        return "sniff"

    def _sniffed_kind(self, entry: _Entry, kind: str, location: str) -> str | None:
        found = _magic(entry.head())
        if kind == "rar":
            if found == "zip":
                return "jar"    # a resource adapter, published like a jar
            if found == "external":
                return "external"
            self.warnings.append(f"{location}: neither a RAR archive nor a resource adapter (zip), skipped")
            return None
        if found == "zstd":
            raise _Unsupported("zstd compression is not supported")
        return "zip-or-jar" if found == "zip" else found

    def _bomb(self, entry: _Entry, location: str) -> bool:
        if (entry.compressed is not None and entry.size is not None and entry.size > SPOOL_SIZE
                and entry.size > BOMB_RATIO * max(entry.compressed, 1)):
            self.warnings.append(f"{location}: expands {entry.size // max(entry.compressed, 1)}:1 to "
                                 f"{entry.size} bytes, skipped as a likely decompression bomb")
            return True
        return False

    def _zip(self, source: bytes | Path, location: str, depth: int, inside_jar: bool = False) -> Iterator[Item]:
        with zipfile.ZipFile(source if isinstance(source, Path) else io.BytesIO(source)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            # A jar's own lockfiles or package.json (webjars) describe the jar, which is identified itself.
            if inside_jar:
                infos = [info for info in infos if info.filename.lower().endswith(JAR_SUFFIXES + (".js",))]
            homes = () if inside_jar else _java_homes(info.filename for info in infos)
            for info in infos:
                yield from self._file(f"{location}!/{info.filename}", info.filename,
                                      _Entry(info.file_size, lambda info=info: archive.open(info),
                                             compressed=info.compress_size), depth, homes)

    def _tar(self, source: bytes | Path, location: str, depth: int) -> Iterator[Item]:
        stored = source.stat().st_size if isinstance(source, Path) else len(source)
        with _open_tar(source) as archive:
            members = archive.getmembers()
            named = {_clean(m.name): m for m in members}
            files = {name: m for name, m in named.items() if m.isfile() or m.islnk()}
            expanded = sum(m.size for m in files.values())
            if expanded > SPOOL_SIZE and expanded > BOMB_RATIO * max(stored, 1):
                self.warnings.append(f"{location}: expands {expanded // max(stored, 1)}:1 to {expanded} bytes, "
                                     f"skipped as a likely decompression bomb")
                return

            def read(name: str) -> bytes | None:
                member = named.get(name)
                return _read_member(archive, member) if member is not None else None

            # Older ``docker save`` output links a layer that two images share instead of storing it twice.
            images = self._image_list(read, lambda name: name in files or (name in named and named[name].issym()),
                                      location)
            if images is not None:
                for tag, layers in images:
                    label = f"{location}!/<{tag}>"
                    if not any(fnmatch(label, pattern) for pattern in self.exclude):
                        yield from self._image(lambda layer: _open_layer(archive, named[layer]), layers, label,
                                               depth)
                return
            homes = _java_homes(files)
            for member in members:
                if member.isfile() or member.islnk():
                    name = _clean(member.name)
                    yield from self._file(f"{location}!/{name}", name, _tar_entry(archive, member), depth, homes)

    # ---- container images -----------------------------------------------------------------------------

    def _image_list(self, read: Callable[[str], bytes | None], has: Callable[[str], bool],
                    location: str) -> list[tuple[str, list[str]]] | None:
        """(tag, layer paths) of each image a ``docker save`` tarball or an OCI image layout holds, or None
        when the container is not an image."""
        if has("manifest.json"):
            images = _docker_images(read("manifest.json"), has)
            if images:
                return images
        if has("index.json") and has("oci-layout"):
            return self._oci_images(read, has, location)
        return None

    def _oci_images(self, read, has, location: str) -> list[tuple[str, list[str]]]:
        images: list[tuple[str, list[str]]] = []
        try:
            index = json.loads(read("index.json") or b"")
        except ValueError:
            index = None
        if not isinstance(index, dict):
            self.warnings.append(f"{location}: OCI index.json cannot be read")
            return images

        def visit(descriptor, name: str | None, platform: str, nesting: int):
            if not isinstance(descriptor, dict) or nesting > 4:
                return
            annotations = descriptor.get("annotations") or {}
            # Image indexes list build attestations next to the images; they hold no filesystem.
            if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
                return
            name = (annotations.get("io.containerd.image.name") or annotations.get("org.opencontainers.image.ref.name")
                    or name)
            described = descriptor.get("platform") or {}
            if described.get("os") == "unknown":
                return
            if described.get("os"):
                platform = "/".join(str(described[k]) for k in ("os", "architecture", "variant") if described.get(k))
            path = _blob_path(descriptor)
            if path is None or not has(path):
                self.warnings.append(f"{location}: manifest {descriptor.get('digest')} is missing from the "
                                     f"layout, skipped")
                return
            try:
                document = json.loads(read(path) or b"")
            except ValueError:
                document = None
            if not isinstance(document, dict):
                return
            if isinstance(document.get("manifests"), list):
                for child in document["manifests"]:
                    visit(child, name, platform, nesting + 1)
                return
            layers = [_blob_path(layer) for layer in document.get("layers") or []
                      if isinstance(layer, dict) and "tar" in str(layer.get("mediaType") or "tar")]
            tag = name or str(descriptor.get("digest", "image"))[:19]
            if platform:
                tag = f"{tag} ({platform})"
            missing = [layer for layer in layers if layer is None or not has(layer)]
            if missing:
                self.warnings.append(f"{location}: <{tag}> lacks {len(missing)} of its layers, skipped")
                return
            images.append((tag, layers))

        for descriptor in index.get("manifests") or []:
            visit(descriptor, None, "", 0)
        return images

    def _image(self, open_layer: Callable[[str], tarfile.TarFile], layers: list[str], location: str,
               depth: int) -> Iterator[Item]:
        """Apply the layers in order (whiteouts included) and walk only the files present in the final image."""
        final: dict[str, int] = {}
        try:
            for index, layer in enumerate(layers):
                added: dict[str, int] = {}
                gone, emptied = set(), set()
                with open_layer(layer) as layer_tar:
                    for member in layer_tar:
                        path = _clean(member.name)
                        head, base = posixpath.split(path)
                        if base == ".wh..wh..opq":
                            emptied.add(head)
                        elif base.startswith(".wh."):
                            gone.add(posixpath.join(head, base[4:]))
                        elif member.isfile() or member.islnk():
                            added[path] = index
                        elif not member.isdir():
                            gone.add(path)
                # Whiteouts hide what the layers below put there, never what their own layer adds.
                if gone or emptied:
                    for path in [p for p in final if _hidden(p, gone, emptied)]:
                        del final[path]
                final.update(added)
        except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError, _Unsupported) as error:
            self.warnings.append(f"{location}: a layer cannot be read ({error}), image skipped")
            return
        homes = _java_homes(final)
        for index, layer in enumerate(layers):
            wanted = {p for p, i in final.items()
                      if i == index and self._kind(p, posixpath.basename(p).lower(), homes) is not None}
            if not wanted:
                continue
            with open_layer(layer) as layer_tar:
                for member in layer_tar:
                    path = _clean(member.name)
                    if path in wanted:
                        yield from self._file(f"{location}/{path}", path, _tar_entry(layer_tar, member), depth,
                                              homes)

    def _external(self, source: bytes | Path, location: str, depth: int) -> Iterator[Item]:
        tool = self.unpacker or next((t for t in ("unrar", "7zz", "7z", "bsdtar") if shutil.which(t)), None)
        if tool is None:
            self.warnings.append(f"{location}: no rar/7z extractor found (install unrar, 7z or bsdtar), skipped")
            return
        with tempfile.TemporaryDirectory(prefix="binwitness-") as work:
            archive_path = source if isinstance(source, Path) else Path(work) / "archive.bin"
            if not isinstance(source, Path):
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
            yield from self._directory(out, location + "!/", depth, follow_links=False)


def _disk_entry(path: Path) -> _Entry:
    return _Entry(path.stat().st_size, lambda: open(path, "rb"), path=path)


def _tar_entry(archive: tarfile.TarFile, member: tarfile.TarInfo) -> _Entry:
    size = member.size
    if member.islnk():
        try:
            size = archive.getmember(member.linkname).size
        except KeyError:
            size = None
    return _Entry(size, lambda: archive.extractfile(member) or io.BytesIO())


@contextlib.contextmanager
def _materialized(entry: _Entry):
    """The entry as bytes, or as a path when it is on disk already or too large to keep in memory."""
    if entry.path is not None:
        yield entry.path
        return
    if entry.size is not None and entry.size <= SPOOL_SIZE:
        yield entry.read()
        return
    handle, name = tempfile.mkstemp(prefix="binwitness-")
    try:
        with os.fdopen(handle, "wb") as target, entry.open() as source:
            shutil.copyfileobj(source, target, 1024 * 1024)
        yield Path(name)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(name)


def _magic(head: bytes) -> str | None:
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith((b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c")):
        return "external"
    if head.startswith(ZSTD_MAGIC):
        return "zstd"
    if head[257:262] == b"ustar":
        return "tar"
    try:
        if head.startswith(b"\x1f\x8b"):
            inner = zlib.decompressobj(31).decompress(head, 512)
        elif head.startswith(b"\xfd7zXZ\x00"):
            inner = lzma.LZMADecompressor().decompress(head, 512)
        else:
            return None
    except (zlib.error, lzma.LZMAError, EOFError):
        return None
    return "tar" if inner[257:262] == b"ustar" else None


def _holds_classes(source: bytes | Path) -> bool:
    """A zip with classes of its own is a jar, whatever it is called; a war keeps them under WEB-INF/."""
    with zipfile.ZipFile(source if isinstance(source, Path) else io.BytesIO(source)) as archive:
        return any(name.endswith(".class") and not name.startswith(("WEB-INF/", "BOOT-INF/"))
                   for name in archive.namelist())


def _open_tar(source: bytes | Path) -> tarfile.TarFile:
    if isinstance(source, Path):
        return tarfile.open(source, mode="r:*")
    return tarfile.open(fileobj=io.BytesIO(source), mode="r:*")


def _clean(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    handle = archive.extractfile(member)
    return handle.read() if handle else b""


def _read_small(path: Path) -> bytes | None:
    """Image metadata (index, manifests, configs) is small; anything large is not metadata."""
    try:
        return path.read_bytes() if path.stat().st_size <= 16 * 1024 ** 2 else None
    except OSError:
        return None


def _may_be_image(files: list[str]) -> bool:
    return "manifest.json" in files or ("index.json" in files and "oci-layout" in files)


def _open_layer(archive: tarfile.TarFile, member: tarfile.TarInfo) -> tarfile.TarFile:
    handle = archive.extractfile(member)
    if handle is None:
        raise _Unsupported(f"{member.name} is not a file")
    if handle.read(4) == ZSTD_MAGIC:
        raise _Unsupported("zstd-compressed layers are not supported")
    handle.seek(0)
    return tarfile.open(fileobj=handle, mode="r:*")


def _open_layer_file(path: Path) -> tarfile.TarFile:
    with open(path, "rb") as handle:
        if handle.read(4) == ZSTD_MAGIC:
            raise _Unsupported("zstd-compressed layers are not supported")
    return tarfile.open(path, mode="r:*")


def _blob_path(descriptor) -> str | None:
    algorithm, _, digest = str((descriptor or {}).get("digest", "")).partition(":")
    if not re.fullmatch(r"[a-z0-9]+", algorithm) or not re.fullmatch(r"[a-f0-9]+", digest):
        return None
    return f"blobs/{algorithm}/{digest}"


def _docker_images(manifest: bytes | None, has: Callable[[str], bool]) -> list[tuple[str, list[str]]]:
    try:
        entries = json.loads(manifest or b"")
    except ValueError:
        return []
    if not isinstance(entries, list):
        return []
    images = []
    for entry in entries:
        layers = entry.get("Layers") if isinstance(entry, dict) else None
        if not layers or not all(isinstance(layer, str) and has(_clean(layer)) for layer in layers):
            return []
        tags = entry.get("RepoTags") or []
        tag = tags[0] if tags else (entry.get("Config") or "image").rsplit("/", 1)[-1][:19]
        images.append((tag, [_clean(layer) for layer in layers]))
    return images


def _hidden(path: str, gone: set[str], emptied: set[str]) -> bool:
    if path in gone:
        return True
    parent = path
    while "/" in parent:
        parent = parent.rsplit("/", 1)[0]
        if parent in gone or parent in emptied:
            return True
    return "" in emptied


def _java_homes(names: Iterable[str]) -> tuple[str, ...]:
    """Directories (with a trailing slash) that hold a JDK or JRE installation."""
    present = set(names)
    homes = []
    for name in present:
        if name == "release" or name.endswith("/release"):
            home = name[:-len("release")]
            if any(home + marker in present for marker in JAVA_HOME_MARKERS):
                homes.append(home)
    return tuple(sorted(homes))


def _is_project_lockfile(parts: list[str]) -> bool:
    """Packages publish their own lockfiles, which ship inside node_modules but were never installed. There,
    only npm's hidden lockfile (``node_modules/.package-lock.json``) describes what is present."""
    if "node_modules" not in parts[:-1]:
        return True
    return parts[-1].lower() == ".package-lock.json" and parts[-2] == "node_modules" \
        and parts.count("node_modules") == 1


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
