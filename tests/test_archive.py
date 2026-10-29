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
