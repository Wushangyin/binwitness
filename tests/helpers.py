"""Synthetic artifacts and a scripted network for tests. No test touches the internet."""
from __future__ import annotations

import io
import json
import tarfile
import zipfile


def make_zip(entries: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content.encode() if isinstance(content, str) else content)
    return buffer.getvalue()


def make_jar(group: str | None = None, artifact: str | None = None, version: str | None = None,
             extra: dict | None = None) -> bytes:
    entries = {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n"}
    if group:
        entries[f"META-INF/maven/{group}/{artifact}/pom.properties"] = (
            f"#Generated\ngroupId={group}\nartifactId={artifact}\nversion={version}\n")
    entries.update(extra or {})
    return make_zip(entries)


def make_tar(entries: dict[str, bytes | str | None]) -> bytes:
    """``None`` content makes a directory entry."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
                continue
            data = content.encode() if isinstance(content, str) else content
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def make_image(layers: list[dict], tag: str = "example/app:1.0") -> bytes:
    entries = {f"layer{i}/layer.tar": make_tar(layer) for i, layer in enumerate(layers)}
    entries["manifest.json"] = json.dumps([{"Config": "config.json", "RepoTags": [tag],
                                            "Layers": [f"layer{i}/layer.tar" for i in range(len(layers))]}])
    entries["config.json"] = "{}"
    return make_tar(entries)


class Served(bytes):
    """A file served the way a static file server does: a ``Range`` request gets 206 and that slice."""

    def __new__(cls, data: bytes, ranges: bool = True):
        served = super().__new__(cls, data)
        served.ranges = ranges
        return served

    def respond(self, headers: dict):
        span = headers.get("Range", "")
        if not (self.ranges and span.startswith("bytes=")):
            return 200, bytes(self), {}
        start, _, end = span[len("bytes="):].partition("-")
        if not start:
            return 206, bytes(self[-int(end):]), {}
        return 206, bytes(self[int(start):int(end) + 1 if end else None]), {}


class ScriptedTransport:
    """Answers requests from a table of URL substrings; records every call."""

    def __init__(self, routes: dict[str, object] | None = None):
        self.routes = routes or {}
        self.calls: list[tuple[str, str, bytes | None]] = []

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body))
        for pattern, answer in self.routes.items():
            if pattern in url:
                if isinstance(answer, Served):
                    return answer.respond(headers)
                if callable(answer):
                    answer = answer(method, url, body)
                if isinstance(answer, tuple):
                    return answer[0], answer[1], {}
                if answer is None:
                    return 404, b"", {}
                payload = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
                return 200, payload, {}
        return 404, b"", {}
