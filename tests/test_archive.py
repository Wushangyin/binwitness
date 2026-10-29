import gzip
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from binwitness import archive
from binwitness.archive import Walker

from helpers import make_image, make_jar, make_tar, make_zip


def walk(tmp_path, name, data, **options):
    path = tmp_path / name
    path.write_bytes(data)
    walker = Walker(**options)
    return walker, [(item.kind, item.location) for item in walker.walk(path)]


def test_fat_jar_yields_itself_and_nested_libraries(tmp_path):
    library = make_jar("org.example", "lib", "1.0")
    app = make_zip({"BOOT-INF/lib/lib-1.0.jar": library, "BOOT-INF/classes/static/app.js": "x" * 2048})
    _, items = walk(tmp_path, "app.jar", app)
    assert items == [("jar", "app.jar"), ("jar", "app.jar!/BOOT-INF/lib/lib-1.0.jar"),
                     ("js", "app.jar!/BOOT-INF/classes/static/app.js")]


def test_zip_in_zip_and_tar_in_zip(tmp_path):
    inner = make_tar({"service/lib/a-1.jar": make_jar()})
    bundle = make_zip({"deploy/service.tar": inner, "README.txt": "hello"})
    _, items = walk(tmp_path, "bundle.zip", bundle)
    assert items == [("jar", "bundle.zip!/deploy/service.tar!/service/lib/a-1.jar")]


def test_image_applies_whiteouts_and_opaque_directories(tmp_path):
    image = make_image([
        {"app/": None, "app/lib/old-1.jar": make_jar(), "app/lib/kept-1.jar": make_jar(),
         "opt/tool/x-1.jar": make_jar()},
        {"app/lib/.wh.old-1.jar": b"", "opt/tool/.wh..wh..opq": b"", "opt/tool/y-1.jar": make_jar()},
    ])
    _, items = walk(tmp_path, "image.tar", image)
    assert sorted(loc for _, loc in items) == ["image.tar!/<example/app:1.0>/app/lib/kept-1.jar",
                                              "image.tar!/<example/app:1.0>/opt/tool/y-1.jar"]


def test_image_can_be_excluded_by_tag(tmp_path):
    image = make_image([{"app/a-1.jar": make_jar()}], tag="registry/other:2")
    _, items = walk(tmp_path, "image.tar", image, exclude=("*<registry/other:*>",))
    assert items == []


def test_java_runtime_jars_are_skipped(tmp_path):
    image = make_image([{"usr/lib/jvm/java-8/jre/lib/rt.jar": make_jar(),
                         "opt/openjdk-11/lib/jrt-fs.jar": make_jar(), "app/app-1.jar": make_jar()}])
    walker, items = walk(tmp_path, "image.tar", image)
    assert [loc.rsplit("/", 1)[1] for _, loc in items] == ["app-1.jar"]
    assert walker.skipped_runtime_jars == 2


def test_lockfiles_and_installed_packages(tmp_path):
    project = tmp_path / "web"
    (project / "node_modules" / "@scope" / "pkg" / "lib").mkdir(parents=True)
    (project / "package-lock.json").write_text("{}")
    (project / "node_modules" / "@scope" / "pkg" / "package.json").write_text("{}")
    (project / "node_modules" / "@scope" / "pkg" / "lib" / "package.json").write_text('{"type": "module"}')
    (project / "node_modules" / "@scope" / "pkg" / "index.js").write_text("x" * 4096)
    walker = Walker()
    items = sorted((i.kind, i.location) for i in walker.walk(project))
    assert items == [("lockfile", "web/package-lock.json"),
                     ("npm-package", "web/node_modules/@scope/pkg/package.json")]


def test_macos_metadata_and_corrupt_archives(tmp_path):
    bundle = make_zip({"__MACOSX/._a.zip": b"junk", "._b.jar": b"junk", "broken.zip": b"not a zip"})
    walker, items = walk(tmp_path, "bundle.zip", bundle)
    assert items == []
    assert len(walker.warnings) == 1 and "broken.zip" in walker.warnings[0]


def test_depth_limit(tmp_path):
    data = make_jar()
    for level in range(4):
        data = make_zip({f"level{level}.zip": data})
    walker, items = walk(tmp_path, "deep.zip", data, max_depth=3)
    assert items == [] and "nested deeper" in walker.warnings[0]


def test_lockfiles_that_packages_ship_inside_node_modules_are_not_the_projects(tmp_path):
    project = tmp_path / "web"
    for name in ("package-lock.json", "node_modules/.package-lock.json", "node_modules/left-pad/yarn.lock",
                 "node_modules/left-pad/package-lock.json", "node_modules/a/node_modules/.package-lock.json"):
        (project / name).parent.mkdir(parents=True, exist_ok=True)
        (project / name).write_text("{}")
    items = sorted((i.kind, i.location) for i in Walker().walk(project))
    assert items == [("lockfile", "web/node_modules/.package-lock.json"), ("lockfile", "web/package-lock.json")]


def oci_layout(layers, name="example/app:1.0"):
    """An OCI image layout as ``docker buildx`` writes it: an index naming an image index, which lists the
    image for one platform and a build attestation."""
    blobs = {}

    def blob(content):
        data = content if isinstance(content, bytes) else json.dumps(content).encode()
        digest = hashlib.sha256(data).hexdigest()
        blobs[f"blobs/sha256/{digest}"] = data
        return f"sha256:{digest}"

    image = blob({"schemaVersion": 2, "config": {"digest": blob({})},
                  "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                              "digest": blob(gzip.compress(make_tar(layer)))} for layer in layers]})
    attestation = blob({"schemaVersion": 2, "layers": [{"mediaType": "application/vnd.in-toto+json",
                                                         "digest": blob(b"{}")}]})
    platforms = blob({"schemaVersion": 2, "manifests": [
        {"digest": image, "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
        {"digest": attestation, "platform": {"os": "unknown", "architecture": "unknown"},
         "annotations": {"vnd.docker.reference.type": "attestation-manifest"}}]})
    return {"oci-layout": '{"imageLayoutVersion": "1.0.0"}', **blobs,
            "index.json": json.dumps({"schemaVersion": 2, "manifests": [
                {"digest": platforms, "annotations": {"io.containerd.image.name": name}}]})}


OCI_LAYERS = [{"app/lib/old-1.jar": make_jar(), "app/lib/kept-1.jar": make_jar()}, {"app/lib/.wh.old-1.jar": b""}]


def test_oci_image_layout_in_a_tarball(tmp_path):
    walker, items = walk(tmp_path, "image.tar", make_tar(oci_layout(OCI_LAYERS)))
    assert items == [("jar", "image.tar!/<example/app:1.0 (linux/arm64/v8)>/app/lib/kept-1.jar")]
    assert walker.warnings == []


def test_oci_image_layout_in_a_directory(tmp_path):
    root = tmp_path / "layout"
    for name, data in oci_layout(OCI_LAYERS).items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data.encode() if isinstance(data, str) else data)
    items = [(i.kind, i.location) for i in Walker().walk(root)]
    assert items == [("jar", "layout/<example/app:1.0 (linux/arm64/v8)>/app/lib/kept-1.jar")]


def test_plugins_and_resource_adapters_are_opened_like_jars(tmp_path):
    plugin = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n", "WEB-INF/lib/a-1.jar": make_jar()})
    adapter = make_zip({"META-INF/ra.xml": "<connector/>", "b-1.jar": make_jar()})
    bundle = make_zip({"plugins/git.hpi": plugin, "plugins/old.jpi": plugin,
                       "app.ear": make_zip({"adapter.rar": adapter, "fake.rar": b"neither"})})
    walker, items = walk(tmp_path, "bundle.zip", bundle)
    assert items == [("jar", "bundle.zip!/plugins/git.hpi"), ("jar", "bundle.zip!/plugins/git.hpi!/WEB-INF/lib/a-1.jar"),
                     ("jar", "bundle.zip!/plugins/old.jpi"), ("jar", "bundle.zip!/plugins/old.jpi!/WEB-INF/lib/a-1.jar"),
                     ("jar", "bundle.zip!/app.ear!/adapter.rar"), ("jar", "bundle.zip!/app.ear!/adapter.rar!/b-1.jar")]
    assert walker.warnings == ["bundle.zip!/app.ear!/fake.rar: neither a RAR archive nor a resource adapter (zip), "
                               "skipped"]


def test_archives_under_unknown_names_are_recognised_by_their_content(tmp_path):
    bundle = make_zip({"payload.bin": make_zip({"lib/c-1.jar": make_jar()}),
                       "classes.dat": make_jar(extra={"org/example/Main.class": b"\xca\xfe\xba\xbe"}),
                       "backup.data": gzip.compress(make_tar({"lib/d-1.jar": make_jar()})),
                       "notes.txt": make_zip({"e-1.jar": make_jar()}), "libc.so.6": make_zip({"f-1.jar": make_jar()})})
    _, items = walk(tmp_path, "bundle.zip", bundle)
    assert items == [("jar", "bundle.zip!/payload.bin!/lib/c-1.jar"), ("jar", "bundle.zip!/classes.dat"),
                     ("jar", "bundle.zip!/backup.data!/lib/d-1.jar")]


def test_links_in_the_named_directory_are_followed_and_each_directory_walked_once(tmp_path):
    real = tmp_path / "real" / "lib"
    real.mkdir(parents=True)
    (real / "a-1.jar").write_bytes(make_jar())
    root = tmp_path / "app"
    root.mkdir()
    try:
        (root / "again").symlink_to(real, target_is_directory=True)
        (root / "lib").symlink_to(real, target_is_directory=True)
        (root / "loop").symlink_to(root, target_is_directory=True)
        (root / "b-1.jar").symlink_to(real / "a-1.jar")
        (root / "gone.jar").symlink_to(tmp_path / "missing.jar")
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    walker = Walker()
    assert [i.location for i in walker.walk(root)] == ["app/b-1.jar", "app/again/a-1.jar"]
    assert walker.warnings == ["app/gone.jar: broken symbolic link, skipped"]


def deflated(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as target:
        for name, data in entries.items():
            target.writestr(name, data)
    return buffer.getvalue()


def test_entries_that_expand_a_hundredfold_are_skipped_as_bombs(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "SPOOL_SIZE", 1024)
    zeros = b"\0" * 200_000
    bundle = deflated({"inner.zip": deflated({"zeros.bin": zeros}) + zeros, "lib/a-1.jar": make_jar(),
                       "layers.tar.gz": gzip.compress(make_tar({"zeros.bin": zeros}))})
    walker, items = walk(tmp_path, "bundle.zip", bundle)
    assert items == [("jar", "bundle.zip!/lib/a-1.jar")]
    assert [w.split(": ", 1)[0] for w in walker.warnings] == ["bundle.zip!/inner.zip", "bundle.zip!/layers.tar.gz"]
    assert all("decompression bomb" in w for w in walker.warnings)


def test_large_entries_are_read_from_a_temporary_file_removed_afterwards(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "SPOOL_SIZE", 64)
    jar = make_jar("org.example", "lib", "1.0")
    path = tmp_path / "bundle.zip"
    path.write_bytes(make_zip({"lib/lib-1.0.jar": jar}))
    seen = [(item.location, item.source, item.read() == jar) for item in Walker().walk(path)]
    assert [(location, same) for location, _, same in seen] == [("bundle.zip!/lib/lib-1.0.jar", True)]
    assert isinstance(seen[0][1], Path) and not seen[0][1].exists()


def test_jars_of_a_java_installation_found_by_its_release_file_are_skipped(tmp_path):
    bundle = make_zip({"opt/runtime/release": "JAVA_VERSION=\"17\"", "opt/runtime/lib/modules": b"",
                       "opt/runtime/lib/vendor-crypto.jar": make_jar(), "app/app-1.jar": make_jar()})
    walker, items = walk(tmp_path, "bundle.zip", bundle)
    assert items == [("jar", "bundle.zip!/app/app-1.jar")] and walker.skipped_runtime_jars == 1
    root = tmp_path / "dist"
    for name in ("runtime/release", "runtime/bin/java", "runtime/lib/vendor-crypto.jar", "app/app-1.jar"):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(make_jar() if name.endswith(".jar") else b"")
    walker = Walker()
    assert [i.location for i in walker.walk(root)] == ["dist/app/app-1.jar"] and walker.skipped_runtime_jars == 1


def test_zstd_compressed_archives_are_named_not_silently_dropped(tmp_path):
    bundle = make_zip({"layer.tar": archive.ZSTD_MAGIC + b"\0" * 64, "blob.tar.zst": archive.ZSTD_MAGIC + b"\0" * 64})
    walker, items = walk(tmp_path, "bundle.zip", bundle)
    assert items == []
    assert sorted(walker.warnings) == [
        "bundle.zip!/blob.tar.zst: cannot open (_Unsupported: zstd compression is not supported)",
        "bundle.zip!/layer.tar: cannot open (_Unsupported: zstd compression is not supported)"]
