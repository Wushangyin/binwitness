"""The MCP service and server. Service tests need no SDK; protocol tests are skipped without the mcp extra."""
import json
import os
import re
import subprocess
import sys
import time

import pytest

from binwitness import upgrades
from binwitness.cli import main
from binwitness.mcp_server import INSTRUCTIONS, PLAN_NOTES, SENDS_SCAN, STATEMENT, Config, Refused, Service
from binwitness.net import Net
from binwitness.output import write_all

from helpers import ScriptedTransport, make_jar
from test_scan import delivery, routes, run  # noqa: F401 (delivery is a fixture)

# Our own wording must never vouch for a component; advisory texts quoted from OSV are not ours.
FORBIDDEN = re.compile(r"\b(safe|safely|clean|secure)\b|no (known )?vulnerabilit", re.I)
TOOLS = {"start_scan", "scan_status", "open_result", "list_scans", "overview", "list_components",
         "list_unidentified", "get_component", "get_vulnerability", "upgrade_plan", "crosscheck", "list_candidates",
         "get_candidate"}


@pytest.fixture
def result_dir(tmp_path, delivery):  # noqa: F811
    result, _ = run(tmp_path / "scan", delivery, ScriptedTransport(routes()))
    out = tmp_path / "out"
    write_all(result, out)
    return out


def service(tmp_path, transport=None, **config):
    net = Net(cache_dir=tmp_path / "served-cache", transport=transport or ScriptedTransport(routes()),
              sleep=lambda s: None, offline=config.get("lookup") == "local")
    return Service(Config(results=tmp_path / "results", **config), net=net)


class FakeProcess:
    def __init__(self, code=None):
        self.code = code

    def poll(self):
        return self.code


class Launcher:
    def __init__(self, code=None):
        self.calls, self.processes, self.code = [], [], code

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        self.processes.append(FakeProcess(self.code))
        return self.processes[-1]


def test_without_a_root_only_opening_a_result_works(tmp_path, result_dir):
    served = service(tmp_path)
    with pytest.raises(Refused, match="--root"):
        served.start_scan([str(result_dir)])
    overview = served.open_result(str(result_dir))
    assert next(iter(overview)) == "coverage"
    coverage = overview["coverage"]
    assert coverage["not_identified"] == {"unidentified_jars": 1, "unmatched_scripts": 0, "bundled_scripts": 0,
                                          "scripts_without_version": 0, "first_party_jars": 1}
    assert coverage["not_covered"] == {}
    assert coverage["lookups_complete"] and coverage["statement"] == STATEMENT
    assert coverage["result"] == str((result_dir / "binwitness.json").resolve())
    assert overview["worst_findings"][0]["id"] == "CVE-2023-0001"
    assert overview["worst_findings"][0]["advice"] == "upgrade to 1.1"
    assert overview["upgrades"]["meaning"]["no-published-fix"] == upgrades.VERDICT_TEXT["no-published-fix"]
    # Opening the same file again keeps its id.
    again = served.open_result(str(result_dir / "binwitness.json"))
    assert again["scan_id"] == overview["scan_id"]
    listed = served.list_scans()
    assert [s["scan_id"] for s in listed["scans"]] == [overview["scan_id"]] and listed["scanning"].startswith("off")


def test_components_are_paged_in_purl_order_with_counts_not_locations(tmp_path, result_dir):
    served = service(tmp_path)
    scan_id = served.open_result(str(result_dir))["scan_id"]
    everything = served.list_components(scan_id, limit=100)
    purls = [c["purl"] for c in everything["components"]]
    assert purls == sorted(purls) and everything["remaining"] == 0
    first = served.list_components(scan_id, limit=1)
    assert (first["returned"], first["remaining"], first["total"]) == (1, len(purls) - 1, len(purls))
    assert all(isinstance(c["locations"], int) for c in everything["components"])
    critical = served.list_components(scan_id, min_severity="critical")
    assert [c["purl"] for c in critical["components"]] == ["pkg:maven/org.example/lib@1.0"]
    assert critical["components"][0]["findings"] == {"CRITICAL": 1} and critical["components"][0]["known_exploited"]
    blocked = served.list_components(scan_id, verdict="no-published-fix")
    assert [c["purl"] for c in blocked["components"]] == ["pkg:maven/io.netty/netty-codec-http@4.1.54.Final"]
    assert served.list_components(scan_id, text="NETTY", limit=100)["total"] == 3
    with pytest.raises(Refused, match="min_severity"):
        served.list_components(scan_id, min_severity="severe")
    with pytest.raises(Refused, match="limit"):
        served.list_components(scan_id, limit=0)


def test_a_component_by_purl_or_name_with_its_findings_and_advice(tmp_path, result_dir):
    served = service(tmp_path)
    scan_id = served.open_result(str(result_dir))["scan_id"]
    lib = served.get_component(scan_id, "org.example:lib@1.0")["component"]
    assert lib["purl"] == "pkg:maven/org.example/lib@1.0" and lib["location_count"] == 1
    assert "locations" not in lib and lib["files"][0]["locations"] == 1
    assert [(f["id"], f["fixed"], f["advice"]) for f in lib["findings"]] == [("CVE-2023-0001", ["1.1"],
                                                                             "upgrade to 1.1")]
    assert lib["upgrade"]["meaning"] == upgrades.VERDICT_TEXT["upgrade"]
    shown = served.get_component(scan_id, "pkg:maven/org.example/lib@1.0", include_locations=True)["component"]
    assert shown["locations"] == ["delivery.zip!/lib/lib-1.0.jar"] and shown["files"][0]["locations"] == \
        ["delivery.zip!/lib/lib-1.0.jar"]
    patched = served.get_component(scan_id, "org.example:patched@2.0")["component"]
    assert patched["findings"] == [] and patched["findings_note"].startswith("OSV has no advisory")
    with pytest.raises(Refused, match="no component netty in this scan; 3 names contain it"):
        served.get_component(scan_id, "netty")
    with pytest.raises(Refused, match="no component"):
        served.get_component(scan_id, "org.example:absent")


def test_a_vulnerability_by_any_alias_with_its_record_unless_lookups_are_local(tmp_path, result_dir):
    served = service(tmp_path)
    scan_id = served.open_result(str(result_dir))["scan_id"]
    answer = served.get_vulnerability(scan_id, "ghsa-aaaa")
    assert answer["vulnerability"]["id"] == "CVE-2023-0001"
    assert answer["affects"] == [{"component": "pkg:maven/org.example/lib@1.0", "fixed": ["1.1"], "via": None,
                                  "advice": "upgrade to 1.1"}]
    record = answer["advisories"][0]
    assert (record["id"], record["source"], record["summary"]) == ("GHSA-aaaa", "api.osv.dev",
                                                                   "flaw in org.example:lib")
    assert record["affected"][0]["ranges"][0]["events"] == [{"introduced": "0"}, {"fixed": "1.1"}]
    local = service(tmp_path / "local", transport=ScriptedTransport({}), lookup="local")
    scan_id = local.open_result(str(result_dir))["scan_id"]
    assert "--lookup local" in local.get_vulnerability(scan_id, "CVE-2023-0001")["advisories"][0]["note"]
    with pytest.raises(Refused, match="not among this scan's findings"):
        local.get_vulnerability(scan_id, "CVE-1999-0001")


def test_the_upgrade_plan_puts_the_worst_first_and_routes_bundled_components_to_their_host(tmp_path, result_dir):
    served = service(tmp_path)
    scan_id = served.open_result(str(result_dir))["scan_id"]
    plan = served.upgrade_plan(scan_id)
    first, second = plan["plan"]
    assert (first["action"], first["component"], first["target"], first["clears"]) == (
        "upgrade", "pkg:maven/org.example/lib@1.0", "1.1", ["CVE-2023-0001"])
    assert first["known_exploited"] and first["worst_severity"] == "CRITICAL"
    assert second["action"] == "change the host" and second["host"] == "pkg:maven/io.netty/netty-all@4.1.54.Final"
    assert second["host_upgrade"] is None  # the host itself has no findings here
    bundled = second["bundled"][0]
    assert (bundled["verdict"], bundled["target"]) == ("no-published-fix", None)
    assert bundled["fix_versions_not_published"] == [{"id": "CVE-2023-0002", "fixed": "9.9"}]
    assert plan["notes"] == [PLAN_NOTES["compatibility"], PLAN_NOTES["bom-managed"]]
    assert plan["not_checked"]["total"] == 0
    assert served.upgrade_plan(scan_id, min_severity="critical")["total"] == 1


def test_lookups_may_only_be_narrowed_and_class_search_needs_the_servers_consent(tmp_path, result_dir):
    launch = Launcher()
    served = Service(Config(results=tmp_path / "results", roots=(tmp_path,), lookup="auto",
                            cache_dir=tmp_path / "c", maven_repos=("https://repo.example.org/m2",)), launch=launch)
    with pytest.raises(Refused, match="up to 'auto'"):
        served.start_scan([str(result_dir)], lookup="online")
    with pytest.raises(Refused, match="--allow-class-search"):
        served.start_scan([str(result_dir)], class_search=True)
    started = served.start_scan([str(result_dir)], lookup="local", upgrade_advice=False,
                                first_party_groups=["com.acme"])
    command, kwargs = launch.calls[0]
    assert command[1:4] == ["-m", "binwitness", "scan"] and command[4] == str(result_dir.resolve())
    joined = " ".join(command)
    assert "--lookup local" in joined and f"--cache-dir {tmp_path / 'c'}" in joined
    assert "--maven-repo https://repo.example.org/m2" in joined and "--first-party-group com.acme" in joined
    assert "--no-upgrades" in command and "--class-search" not in command and "--no-vulns" not in command
    # The protocol runs over the server's stdin and stdout.
    assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["stdout"].name.endswith("summary.txt")
    assert served.scan_status(started["scan_id"])["state"] == "running"
    with pytest.raises(Refused, match="still running"):
        served.start_scan([str(result_dir)])
    with pytest.raises(Refused, match="has no result yet"):
        served.overview(started["scan_id"])


def test_paths_outside_the_roots_and_odd_scan_ids_are_refused(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    paths = [str(outside), str(root / ".." / "outside")]
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
        paths.append(str(root / "link"))
    except OSError:  # Windows without the symlink privilege
        pass
    served = Service(Config(results=tmp_path / "results", roots=(root,)), launch=Launcher())
    for path in paths:
        with pytest.raises(Refused, match="outside the directories"):
            served.start_scan([path])
    with pytest.raises(Refused, match="not found"):
        served.start_scan([str(root / "absent")])
    # A directory outside the results that looks like a scan must not be reachable by its relative path.
    (tmp_path / "results").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "job.json").write_text("{}")
    for scan_id in ("../elsewhere", "", "a/b"):
        with pytest.raises(Refused, match="no scan"):
            served.scan_status(scan_id)


def test_a_failed_scan_reports_its_exit_code_and_the_end_of_its_log(tmp_path):
    served = Service(Config(results=tmp_path / "results", roots=(tmp_path,)), launch=Launcher(code=2))
    scan_id = served.start_scan([str(tmp_path)])["scan_id"]
    (tmp_path / "results" / scan_id / "scan.log").write_text("starting\nbinwitness scan: error: boom\n")
    status = served.scan_status(scan_id)
    assert (status["state"], status["exit_code"]) == ("failed", 2)
    assert status["log_tail"] == ["starting", "binwitness scan: error: boom"]
    # A later server, which did not start it, still knows how it ended.
    later = Service(Config(results=tmp_path / "results", roots=(tmp_path,)))
    assert later.scan_status(scan_id)["state"] == "failed"
    assert later.list_scans()["scans"][0]["state"] == "failed"


def test_crosscheck_counts_failed_lookups_as_incomplete(tmp_path, result_dir, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    other = tmp_path / "other.csv"
    other.write_text("component,version,vulnerability\norg.example:lib,1.0,CVE-2023-0001\n"
                     "org.example:lib,1.0,CVE-2024-9999\n")
    transport = ScriptedTransport({"api.github.com": lambda m, url, b: (403, b"{}", {}), **routes()})
    served = service(tmp_path, transport=transport, roots=(tmp_path,))
    scan_id = served.open_result(str(result_dir))["scan_id"]
    answer = served.crosscheck(scan_id, str(other))
    assert answer["summary"]["findings_in_both"] == 1
    assert answer["summary"]["only_theirs_by_class"] == {"lookup-failed": 1}
    assert answer["incomplete"]["lookup_failed"] == 1
    assert json.loads(open(answer["report"], encoding="utf-8").read())["only_theirs"][0]["id"] == "CVE-2024-9999"
    local = service(tmp_path / "local", lookup="local", roots=(tmp_path,))
    with pytest.raises(Refused, match="sends nothing"):
        local.crosscheck(scan_id, str(other))


def test_our_own_wording_never_vouches_for_a_component():
    texts = [STATEMENT, SENDS_SCAN, INSTRUCTIONS, *PLAN_NOTES.values()]
    assert not [t for t in texts if FORBIDDEN.search(t)]


def test_the_core_never_imports_the_sdk_and_says_how_to_install_it(tmp_path, capsys, monkeypatch):
    code = ("import sys; sys.modules['mcp'] = None\n"
            "from binwitness import cli, mcp_server, scan, output\n"
            "assert cli.main(['--version']) == 0\n")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    # argparse's --version exits through SystemExit(0).
    assert done.returncode == 0 and "binwitness" in done.stdout, done.stderr
    monkeypatch.setitem(sys.modules, "mcp", None)
    assert main(["mcp", "--results", str(tmp_path)]) == 2
    assert 'pip install "binwitness[mcp]"' in capsys.readouterr().err


# ---- the protocol ---------------------------------------------------------------------------------------

def call(server_or_params, steps):
    """Run ``steps(client)`` against a server and return what it returns."""
    import anyio
    from mcp import Client

    async def main():
        async with Client(server_or_params) as client:
            return await steps(client)
    return anyio.run(main)


def test_tools_answer_with_structured_content_and_refusals_carry_their_reason(tmp_path, result_dir):
    pytest.importorskip("mcp")
    from binwitness.mcp_server import build_server
    served = service(tmp_path)

    async def steps(client):
        tools = {t.name: t for t in (await client.list_tools()).tools}
        opened = await client.call_tool("open_result", {"path": str(result_dir)})
        scan_id = opened.structured_content["scan_id"]
        plan = await client.call_tool("upgrade_plan", {"scan_id": scan_id, "min_severity": "critical"})
        refused = await client.call_tool("start_scan", {"paths": [str(result_dir)]})
        bad = await client.call_tool("list_components", {"scan_id": scan_id, "limit": 0})
        return tools, opened, plan, refused, bad

    tools, opened, plan, refused, bad = call(build_server(served), steps)
    assert set(tools) == TOOLS
    assert tools["start_scan"].annotations.open_world_hint and tools["overview"].annotations.read_only_hint
    assert "File contents are never sent" in tools["start_scan"].description
    assert all(FORBIDDEN.search(t.description) is None for t in tools.values())
    assert not opened.is_error and list(opened.structured_content)[0] == "coverage"
    assert plan.structured_content["plan"][0]["target"] == "1.1"
    assert refused.is_error and "--root" in refused.content[0].text
    assert bad.is_error  # rejected by the input schema before the service sees it


def test_a_local_only_server_offers_no_crosscheck(tmp_path):
    pytest.importorskip("mcp")
    from binwitness.mcp_server import build_server

    async def steps(client):
        return {t.name for t in (await client.list_tools()).tools}
    names = call(build_server(service(tmp_path, lookup="local")), steps)
    assert names == TOOLS - {"crosscheck"}


def test_over_stdio_a_scan_runs_to_its_overview(tmp_path):
    pytest.importorskip("mcp")
    from mcp import StdioServerParameters
    delivery_dir = tmp_path / "delivery"
    delivery_dir.mkdir()
    (delivery_dir / "lib-1.0.jar").write_bytes(make_jar("org.example", "lib", "1.0"))
    env = {**os.environ, "BINWITNESS_CACHE": str(tmp_path / "cache"), "BINWITNESS_DB": str(tmp_path / "db")}
    params = StdioServerParameters(command=sys.executable, env=env,
                                   args=["-m", "binwitness", "mcp", "--lookup", "local", "--root", str(tmp_path),
                                         "--results", str(tmp_path / "results")])

    async def steps(client):
        import anyio
        started = (await client.call_tool("start_scan", {"paths": [str(delivery_dir)]})).structured_content
        deadline = time.monotonic() + 60
        while True:
            status = (await client.call_tool("scan_status", {"scan_id": started["scan_id"]})).structured_content
            if status["state"] != "running" or time.monotonic() > deadline:
                break
            await anyio.sleep(0.2)  # polling the scan's state, which is the signal
        overview = (await client.call_tool("overview", {"scan_id": started["scan_id"]})).structured_content
        return started, status, overview

    started, status, overview = call(params, steps)
    assert status["state"] == "finished", status
    assert overview["components"]["total"] == 1 and overview["coverage"]["lookup"] == "local"
    # Offline, the jar's checksum could not be compared with the published one; the coverage says so.
    assert not overview["coverage"]["lookups_complete"]
    summary = (tmp_path / "results" / started["scan_id"] / "summary.txt").read_text("utf-8")
    assert summary.startswith("components")


def named_components(*specs):
    out = []
    for ecosystem, name, version in specs:
        path = name.replace(":", "/") if ecosystem == "maven" else name.replace("@", "%40")
        out.append({"purl": f"pkg:{ecosystem}/{path}@{version}", "ecosystem": ecosystem, "name": name,
                    "version": version})
    return {"components": out}


def test_an_exact_name_wins_over_a_part_of_one():
    found = named_components(("maven", "org.springframework:spring-web", "5.3.4"),
                             ("maven", "org.springframework:spring-webmvc", "5.3.4"),
                             ("maven", "org.springframework:spring-websocket", "5.3.4"),
                             ("npm", "@babel/core", "7.0.0"))
    assert Service._find(found, "spring-web")["name"] == "org.springframework:spring-web"
    assert Service._find(found, "org.springframework:spring-web")["version"] == "5.3.4"
    assert Service._find(found, "@babel/core")["version"] == "7.0.0"
    assert Service._find(found, "@babel/core@7.0.0")["name"] == "@babel/core"
    two = named_components(("maven", "org.springframework:spring-web", "5.3.4"),
                           ("maven", "org.springframework:spring-web", "5.3.20"))
    assert Service._find(two, "spring-web@5.3.20")["version"] == "5.3.20"
    with pytest.raises(Refused, match="matches 2 components.*give the version"):
        Service._find(two, "spring-web")


def test_a_part_of_a_name_is_offered_never_taken():
    # log4j 1.x asked for, log4j-api 2.x in the scan: answering with it would be another library's findings.
    found = named_components(("maven", "com.alibaba.fastjson2:fastjson2", "2.0.43"),
                             ("maven", "org.apache.logging.log4j:log4j-api", "2.17.1"),
                             ("maven", "org.springframework:spring-webmvc", "5.3.4"))
    for wanted, offered in (("log4j:log4j", "log4j-api@2.17.1"), ("com.alibaba:fastjson", None),
                            ("fastjson", "fastjson2@2.0.43"), ("webmvc", "spring-webmvc@5.3.4")):
        with pytest.raises(Refused) as refused:
            Service._find(found, wanted)
        message = str(refused.value)
        assert message.startswith(f"no component {wanted} in this scan")
        assert (offered in message) if offered else "contain" not in message


def test_a_release_family_is_one_step_with_what_each_member_would_need_alone(tmp_path, result_dir):
    result = json.loads((result_dir / "binwitness.json").read_text())
    lib = next(c for c in result["components"] if c["name"] == "org.example:lib")
    lib["upgrade_family"] = "org.example@1.0"
    result["upgrade_families"] = [{
        "family": "org.example@1.0", "group": "org.example", "version": "1.0",
        "members": [lib["purl"], "pkg:maven/org.example/other@1.0"], "verdict": "upgrade", "target": "1.2",
        "clears": ["CVE-2023-0001"], "remaining": [], "introduced": [], "caveats": [],
        "per_member": [{"component": lib["purl"], "own_target": "1.1", "remaining": [], "introduced": []},
                       {"component": "pkg:maven/org.example/other@1.0", "own_target": None, "remaining": [],
                        "introduced": []}]}]
    (result_dir / "binwitness.json").write_text(json.dumps(result))
    served = service(tmp_path)
    scan_id = served.open_result(str(result_dir))["scan_id"]
    plan = served.upgrade_plan(scan_id)
    first = plan["plan"][0]
    assert (first["family"], first["target"], first["clears"]) == ("org.example@1.0", "1.2", ["CVE-2023-0001"])
    assert not any(step.get("component") == lib["purl"] for step in plan["plan"])
    assert PLAN_NOTES["family"] in plan["notes"]
    shown = served.get_component(scan_id, "org.example:lib@1.0")["component"]
    assert shown["upgrade_family"]["target"] == "1.2" and shown["upgrade"]["target"] == "1.1"
    assert shown["findings"][0]["advice"] == "upgrade to 1.2 with the other 1 org.example artifact"


def test_a_family_step_lists_only_the_members_with_something_to_say(tmp_path, result_dir):
    result = json.loads((result_dir / "binwitness.json").read_text())
    lib = next(c for c in result["components"] if c["name"] == "org.example:lib")
    lib["upgrade_family"] = "org.example@1.0"
    quiet = {"component": "pkg:maven/org.example/quiet@1.0", "own_target": None, "remaining": [], "introduced": []}
    left = {"component": "pkg:maven/org.example/left@1.0", "own_target": None, "remaining": ["CVE-2023-0009"],
            "introduced": []}
    result["upgrade_families"] = [{
        "family": "org.example@1.0", "group": "org.example", "version": "1.0",
        "members": [lib["purl"], quiet["component"], left["component"]], "verdict": "upgrade", "target": "1.2",
        "clears": ["CVE-2023-0001"], "remaining": [], "introduced": [], "caveats": [],
        "per_member": [{"component": lib["purl"], "own_target": "1.1", "remaining": [], "introduced": []}, quiet,
                       left]}]
    (result_dir / "binwitness.json").write_text(json.dumps(result))
    served = service(tmp_path)
    step = served.upgrade_plan(served.open_result(str(result_dir))["scan_id"])["plan"][0]
    assert len(step["members"]) == 3
    assert [m["component"] for m in step["per_member"]] == [lib["purl"], left["component"]]
