"""Which delivered jar depends on which: the dependencies a jar's POM declares, among the jars delivered with it.

A POM names what its project was built against, by groupId and artifactId; the delivery holds what the build
resolved. An edge is drawn where a declared dependency is one of the jars of the same unit: the innermost
archive the jar is in (a war, a Spring Boot jar, a distribution zip), the container image, or the scanned
directory; and the jar itself for the jars it carries (a Spring Boot jar's ``BOOT-INF/lib``). Versions are not
compared: the version delivered is the one the build chose.
"""
from __future__ import annotations

import re

# Test dependencies are not shipped; whatever else is declared and delivered is used when it is there
# (a provided or optional dependency the delivery carries anyway).
_NOT_SHIPPED = {"test"}
# Sections whose <dependency> elements are not the project's own: managed versions, plugins' classpaths,
# profiles that may not be active.
_OTHER_SECTIONS = re.compile(r"<(dependencyManagement|build|profiles|reporting)\b.*?</\1\s*>", re.S)


def declared(pom: str) -> list[str]:
    """``groupId:artifactId`` of the dependencies a POM declares for its project, test ones left out. A
    groupId the POM leaves to a property it does not define itself stays as written (``${netty.group}``)."""
    text = _OTHER_SECTIONS.sub("", re.sub(r"<!--.*?-->", "", pom, flags=re.S))
    parent = re.search(r"<parent>(.*?)</parent>", text, re.S)
    head = re.sub(r"<(parent|dependencies|properties)\b.*?</\1\s*>", "", text, flags=re.S)
    parent_group = _field(parent.group(1), "groupId") if parent else None
    group = _field(head, "groupId") or parent_group
    properties = {}
    block = re.search(r"<properties>(.*?)</properties>", text, re.S)
    if block:
        properties.update(re.findall(r"<([\w.-]+)>\s*([^<]*?)\s*</\1>", block.group(1)))
    for key in ("project.groupId", "pom.groupId", "groupId"):
        if group:
            properties[key] = group
    for key in ("project.parent.groupId", "parent.groupId"):
        if parent_group:
            properties[key] = parent_group
    out = []
    for body in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
        body = re.sub(r"<exclusions>.*?</exclusions>", "", body, flags=re.S)
        dependency_group, artifact = _field(body, "groupId"), _field(body, "artifactId")
        if not (dependency_group and artifact) or (_field(body, "scope") or "compile") in _NOT_SHIPPED:
            continue
        name = f"{_expand(dependency_group, properties)}:{_expand(artifact, properties)}"
        if "${" not in name.split(":", 1)[1] and name not in out:
            out.append(name)
    return out


def _field(body: str, name: str) -> str | None:
    match = re.search(rf"<{name}>\s*([^<]+?)\s*</{name}>", body)
    return match.group(1) if match else None


def _expand(value: str, properties: dict[str, str]) -> str:
    for _ in range(3):  # a property defined by another
        expanded = re.sub(r"\$\{([^}]+)\}", lambda m: properties.get(m.group(1), m.group(0)), value)
        if expanded == value:
            break
        value = expanded
    return value


def unit(location: str) -> str:
    """What a jar at ``location`` is delivered with: the innermost archive it is in, the image when that is a
    container image, the scanned directory when it is in none."""
    head, separator, tail = location.rpartition("!/")
    if not separator:
        opening = location.find("/<")  # an image unpacked in a directory
        if opening >= 0 and ">" in location[opening:]:
            return location[:location.index(">", opening) + 1]
        return location.split("/", 1)[0] if "/" in location else ""
    if tail.startswith("<") and ">" in tail:
        return f"{head}!/{tail[:tail.index('>') + 1]}"
    return head


def nodes(result: dict) -> list[dict]:
    """Every delivered jar file once: its SHA-1, the coordinates it can be depended on by, its locations and the
    dependencies it declares (None when that is not known)."""
    out = []
    for component in result["components"]:
        if component["ecosystem"] != "maven":
            continue
        for file in component["files"]:
            keys = [component["name"]] + [_name_of(p) for p in file.get("also_published_as", [])
                                          if p.startswith("pkg:maven/")]
            out.append({"sha1": file["sha1"], "keys": list(dict.fromkeys(keys)), "locations": file["locations"],
                        "declared": (file.get("dependencies") or {}).get("declared"), "component": component})
    for kind in ("first_party", "unidentified"):
        for jar in result[kind]:
            if jar.get("kind", "jar") != "jar":
                continue
            coordinate = jar.get("coordinate")
            out.append({"sha1": jar["sha1"], "keys": [coordinate.rsplit(":", 1)[0]] if coordinate else [],
                        "locations": jar["locations"], "declared": (jar.get("dependencies") or {}).get("declared"),
                        "component": None})
    return out


def _name_of(maven_purl: str) -> str:
    return maven_purl[len("pkg:maven/"):].rsplit("@", 1)[0].replace("/", ":", 1)


def edges(result: dict) -> dict[str, set[str]]:
    """SHA-1 of each jar whose dependencies are known -> SHA-1s of the delivered jars it depends on."""
    found = nodes(result)
    by_unit: dict[str, dict[str, set[str]]] = {}
    for node in found:
        for location in node["locations"]:
            index = by_unit.setdefault(unit(location), {})
            for key in node["keys"]:
                index.setdefault(key, set()).add(node["sha1"])
    out = {}
    for node in found:
        if node["declared"] is None:
            continue
        targets = set()
        for location in node["locations"]:
            # Its unit, and the jars it carries itself.
            for index in (by_unit.get(unit(location), {}), by_unit.get(location, {})):
                for name in node["declared"]:
                    group, artifact = name.rsplit(":", 1)
                    if "${" not in group:
                        targets |= index.get(name, set())
                        continue
                    # A groupId from a parent's property: the artifactId, when one coordinate of the unit has it.
                    named = [key for key in index if key.rsplit(":", 1)[1] == artifact]
                    if len(named) == 1:
                        targets |= index[named[0]]
        targets.discard(node["sha1"])
        out[node["sha1"]] = targets
    return out


def attach(result: dict) -> dict:
    """Sets ``depends_on`` on components and first-party and unidentified jars (purls, and ``file:<sha1>`` for
    jars without one; None when no file of it says what it depends on); returns the summary."""
    graph = edges(result)
    ref = {}
    for component in result["components"]:
        for file in component["files"]:
            ref[file["sha1"]] = component["purl"]
    for kind in ("first_party", "unidentified"):
        for jar in result[kind]:
            ref.setdefault(jar["sha1"], f"file:{jar['sha1']}")
    for component in result["components"]:
        known = [graph[f["sha1"]] for f in component["files"] if f["sha1"] in graph]
        component["depends_on"] = sorted({ref[t] for targets in known for t in targets}) if known else None
    for kind in ("first_party", "unidentified"):
        for jar in result[kind]:
            jar["depends_on"] = sorted(ref[t] for t in graph[jar["sha1"]]) if jar["sha1"] in graph else None
    sources = [(file.get("dependencies") or {}).get("source") for c in result["components"] for file in c["files"]
               if c["ecosystem"] == "maven"]
    sources += [(jar.get("dependencies") or {}).get("source") for kind in ("first_party", "unidentified")
                for jar in result[kind] if jar.get("kind", "jar") == "jar"]
    return {"jars": len(sources), "declared_in_jar": sources.count("jar: pom.xml"),
            "from_published_pom": sum(1 for s in sources if s and s != "jar: pom.xml"),
            "not_known": sources.count(None), "edges": sum(len(t) for t in graph.values())}


def containers(location: str):
    """Locations of the archives a location sits in, outermost first: ``a.zip!/b.jar!/c.jar`` -> a.zip, a.zip!/b.jar."""
    parts = location.split("!/")
    return ("!/".join(parts[:i]) for i in range(1, len(parts)))


def input_of(location: str, names: list[str]) -> int | None:
    """Index of the input ``location`` was found in; inputs are named by their file or directory name."""
    for number, name in enumerate(names):
        if location == name or location.startswith((f"{name}!/", f"{name}/")):
            return number
    # "." is named by the directory it resolves to; what is found in it is not.
    return 0 if len(names) == 1 else None

