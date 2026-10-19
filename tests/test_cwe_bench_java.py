"""CWE-Bench-Java loader, offline with tiny fake CSVs."""
from benchmarks.cwe_bench_java import (load_projects, select, labels_for, norm_cwe,
                                       cve_year)

PROJECTS = """id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,github_tag,github_url,advisory_id,buggy_commit_id,fix_commit_ids
1,a__x_CVE-2021-1_1.0,CVE-2021-1,CWE-022,Path,a,x,1.0,https://github.com/a/x,GHSA-1,aaa,f1;f2
2,b__y_CVE-2023-2_2.0,CVE-2023-2,CWE-022,Path,b,y,2.0,https://github.com/b/y,GHSA-2,bbb,f3
3,c__z_CVE-2022-3_3.0,CVE-2022-3,CWE-79,XSS,c,z,3.0,https://github.com/c/z,GHSA-3,ccc,f4
4,d__w_CVE-2022-4_4.0,CVE-2022-4,CWE-094,Code,d,w,4.0,https://github.com/d/w,GHSA-4,ddd,f5
"""
FIXES = """project_slug,cve,github_username,github_repository_name,commit,file,class,class_start,class_end,method,method_start,method_end,signature
a__x_CVE-2021-1_1.0,CVE-2021-1,a,x,f1,src/A.java,A,1,90,load,10,20,void load(String)
a__x_CVE-2021-1_1.0,CVE-2021-1,a,x,f2,src/A.java,A,1,90,load,10,22,void load(String)
b__y_CVE-2023-2_2.0,CVE-2023-2,b,y,f3,src/B.java,B,5,50,,,,
c__z_CVE-2022-3_3.0,CVE-2022-3,c,z,f4,web/C.java,C,1,40,render,8,15,String render()
"""


def _data(tmp_path):
    (tmp_path / "project_info.csv").write_text(PROJECTS)
    (tmp_path / "fix_info.csv").write_text(FIXES)
    return load_projects(tmp_path)


def test_load_and_normalize(tmp_path):
    ps = _data(tmp_path)
    assert len(ps) == 4
    assert ps["a__x_CVE-2021-1_1.0"].cwe == "CWE-22"
    assert ps["a__x_CVE-2021-1_1.0"].fix_commits == ["f1", "f2"]
    assert ps["d__w_CVE-2022-4_4.0"].methods == []   # no ground truth
    assert norm_cwe("CWE-094") == "CWE-94" and cve_year("CVE-2023-2") == 2023


def test_select_is_seeded_stratified_and_skips_unscorable(tmp_path):
    ps = _data(tmp_path)
    a = select(ps, ["22", "79", "94"], 5, seed=1)
    assert [p.slug for p in a] == [p.slug for p in select(ps, ["22", "79", "94"], 5, 1)]
    assert {p.cwe for p in a} == {"CWE-22", "CWE-79"}   # CWE-94 has no ground truth
    assert [p.slug for p in select(ps, ["22"], 0, 0, min_year=2023)] == ["b__y_CVE-2023-2_2.0"]
    assert [p.slug for p in select(ps, ["22"], 0, 0, only=["a__x"])] == ["a__x_CVE-2021-1_1.0"]


def test_labels_dedupe_and_prefix(tmp_path):
    ps = _data(tmp_path)
    la = labels_for(ps["a__x_CVE-2021-1_1.0"])
    assert len(la) == 1   # same method fixed by two commits counts once
    assert la[0]["file"] == "a__x_CVE-2021-1_1.0/src/A.java"
    assert la[0]["bug_class"] == "path" and la[0]["method"] == "load"
    lb = labels_for(ps["b__y_CVE-2023-2_2.0"])
    assert lb[0]["method"] == "" and lb[0]["line"] == 5   # class-level fix
    assert labels_for(ps["c__z_CVE-2022-3_3.0"])[0]["bug_class"] == "xss"


def test_test_file_labels_dropped(tmp_path):
    from benchmarks.cwe_bench_java import Project, FixedMethod
    p = Project("s", "CVE-2020-1", "CWE-22", "u", "t", "c", [], "")
    p.methods = [FixedMethod("src/main/java/A.java", "A", "load", "", 3),
                 FixedMethod("src/test/java/ATest.java", "ATest", "t1", "", 4)]
    assert [l["method"] for l in labels_for(p)] == ["load"]
    p.methods = p.methods[1:]   # only tests: keep them rather than lose the CVE
    assert [l["method"] for l in labels_for(p)] == ["t1"]


def _project_repo(tmp_path):
    proj = tmp_path / "repo" / "acme__app_CVE-2021-9_1.0" / "src" / "main" / "java"
    proj.mkdir(parents=True)
    (proj / "Files.java").write_text(
        "class Files {\n"
        "  void serve(String name) {\n"
        "    java.io.File f = new java.io.File(base, name);\n"
        "  }\n"
        "  void other() {\n"
        "    int x = 1;\n"
        "  }\n"
        "}\n")
    (proj / "Math.java").write_text("class Math { int add(int a, int b) { return a + b; } }\n")
    test = tmp_path / "repo" / "acme__app_CVE-2021-9_1.0" / "src" / "test" / "java"
    test.mkdir(parents=True)
    (test / "FilesTest.java").write_text("class FilesTest { void t() { new java.io.File(\"x\"); } }\n")
    labels = [{"file": "acme__app_CVE-2021-9_1.0/src/main/java/Files.java", "line": 2,
               "bug_class": "path", "cve": "CVE-2021-9", "project": "acme__app_CVE-2021-9_1.0",
               "method": "serve", "class": "Files"}]
    return tmp_path / "repo", labels


def test_project_units_prefilter_and_scope(tmp_path):
    from auditor.tools import Workspace
    from auditor.units import build_project_units
    repo, _ = _project_repo(tmp_path)
    units, stats = build_project_units(Workspace(str(repo)), ["path"])
    assert [u.id for u in units] == ["acme__app_CVE-2021-9_1.0/src/main/java/Files.java"]
    assert units[0].root == "acme__app_CVE-2021-9_1.0"
    assert stats["acme__app_CVE-2021-9_1.0"] == {"files": 3, "tests": 1, "non_product": 0,
                                                 "kept": 1}
    units, _ = build_project_units(Workspace(str(repo)), ["path"], prefilter=False)
    assert len(units) == 2   # Math.java kept without the pre-filter, test still dropped


def test_method_scoring(tmp_path):
    from eval.metrics import score, default_mode
    repo, labels = _project_repo(tmp_path)
    f = labels[0]["file"]
    assert default_mode(labels) == "method"
    hit = score([{"bug_class": "path", "file": f, "line": 3}], labels, "method", repo)
    assert hit["tp"] == 1 and hit["on_target_findings"] == 1
    near = score([{"bug_class": "path", "file": f, "line": 6}], labels, "method", repo)
    assert near["tp"] == 0 and near["file_recall"] == 1.0 and near["off_target_findings"] == 1
    wrong_class = score([{"bug_class": "xss", "file": f, "line": 3}], labels, "method", repo)
    assert wrong_class["tp"] == 0 and wrong_class["file_recall"] == 0.0


def test_project_units_skip_non_java_and_demo_code(tmp_path):
    from auditor.tools import Workspace
    from auditor.units import build_project_units
    repo, _ = _project_repo(tmp_path)
    base = repo / "acme__app_CVE-2021-9_1.0"
    for rel in ("docs/site.js", "web/app.min.js", "samples/demo/src/D.java",
                "apps/showcase/src/S.java", "acme-sample-app/src/X.java"):
        f = base / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("class X { void f() { new java.io.File(\"x\"); } }\n")
    units, stats = build_project_units(Workspace(str(repo)), ["path"])
    assert [u.id.split("/", 1)[1] for u in units] == ["src/main/java/Files.java"]
    assert stats["acme__app_CVE-2021-9_1.0"]["non_product"] == 3   # .js never counted


def test_max_files_swaps_big_projects(tmp_path, monkeypatch):
    import json
    import sys
    import benchmarks.cwe_bench_java as cbj
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "project_info.csv").write_text(PROJECTS)
    (tmp_path / "data" / "fix_info.csv").write_text(FIXES)
    sizes = {"a__x_CVE-2021-1_1.0": 900, "b__y_CVE-2023-2_2.0": 40}

    def fake_fetch(p, root):
        (root / p.slug).mkdir(parents=True, exist_ok=True)
        return True, "abc"
    monkeypatch.setattr(cbj, "fetch_project", fake_fetch)
    monkeypatch.setattr(cbj, "audited_files", lambda d: sizes.get(d.name, 1))
    monkeypatch.setattr(cbj, "project_size", lambda d: {})
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["x", "--data-dir", str(tmp_path / "data"), "--cwes", "22",
                                      "--per-cwe", "1", "--fetch", "--max-files", "100",
                                      "--out-dir", str(out)])
    cbj.main()
    sel = json.loads((out / "selection.json").read_text())
    assert [p["slug"] for p in sel["projects"]] == ["b__y_CVE-2023-2_2.0"]
    assert [s["slug"] for s in sel["skipped_for_size"]] in ([], ["a__x_CVE-2021-1_1.0"])
    assert not (out / "projects" / "a__x_CVE-2021-1_1.0").exists()   # moved out of the way
    assert {l["project"] for l in json.loads((out / "labels.json").read_text())} == \
        {"b__y_CVE-2023-2_2.0"}


def test_space_check_stops_cleanly(tmp_path):
    import pytest
    from benchmarks.cwe_bench_java import ensure_space, free_gb
    ensure_space(tmp_path / "not" / "made" / "yet", 0.0)   # walks up to an existing dir
    with pytest.raises(SystemExit) as e:
        ensure_space(tmp_path, free_gb(tmp_path) + 1000)
    assert "stopping" in str(e.value) and "rerun" in str(e.value)


def _run_loader(tmp_path, monkeypatch, fetch, sizes, extra):
    import json
    import sys
    import benchmarks.cwe_bench_java as cbj
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "project_info.csv").write_text(PROJECTS)
    (data / "fix_info.csv").write_text(FIXES)
    monkeypatch.setattr(cbj, "fetch_project", fetch)
    monkeypatch.setattr(cbj, "audited_files", lambda d: sizes.get(d.name, 1))
    monkeypatch.setattr(cbj, "project_size", lambda d: {})
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["x", "--data-dir", str(data), "--cwes", "22", "79",
                                      "--fetch", "--out-dir", str(out)] + extra)
    cbj.main()
    return (json.loads((out / "selection.json").read_text()),
            json.loads((out / "labels.json").read_text()), out)


def test_full_disk_stops_instead_of_swapping_cves(tmp_path, monkeypatch):
    import pytest
    import benchmarks.cwe_bench_java as cbj
    monkeypatch.setattr(cbj, "free_gb", lambda p: 0.5)   # disk is full
    with pytest.raises(SystemExit) as e:
        _run_loader(tmp_path, monkeypatch, lambda p, r: (False, "x"), {},
                    ["--per-cwe", "1", "--max-files", "100"])
    assert "GB free" in str(e.value)


def test_failed_fetch_gets_no_labels(tmp_path, monkeypatch):
    def fetch(p, root):
        if p.slug.startswith("a__"):
            return False, "could not fetch commit or tag"   # e.g. repo deleted upstream
        (root / p.slug).mkdir(parents=True, exist_ok=True)
        (root / p.slug / ".fetched").write_text("ok")
        return True, "abc"
    sel, labels, _ = _run_loader(tmp_path, monkeypatch, fetch, {}, ["--per-cwe", "0"])
    assert {l["project"] for l in labels} == {"b__y_CVE-2023-2_2.0", "c__z_CVE-2022-3_3.0"}
    assert any(e["slug"].startswith("a__") and e["fetched"] is False for e in sel["projects"])


def test_stale_projects_from_earlier_runs_are_removed(tmp_path, monkeypatch):
    def fetch(p, root):
        (root / p.slug).mkdir(parents=True, exist_ok=True)
        (root / p.slug / ".fetched").write_text("ok")
        return True, "abc"
    stale = tmp_path / "out" / "projects" / "old__thing_CVE-2019-1_1.0"
    stale.mkdir(parents=True)
    _, _, out = _run_loader(tmp_path, monkeypatch, fetch, {}, ["--per-cwe", "0"])
    assert not stale.exists()
    assert (out / "projects" / "c__z_CVE-2022-3_3.0").exists()


def test_failed_fetch_leaves_no_partial_folder(tmp_path, monkeypatch):
    import benchmarks.cwe_bench_java as cbj
    from benchmarks.cwe_bench_java import Project, fetch_project
    monkeypatch.setattr(cbj, "_git", lambda args, cwd: args[0] in ("init", "remote"))
    p = Project("s__p_CVE-2020-1_1", "CVE-2020-1", "CWE-22", "u", "t", "c", [], "")
    assert fetch_project(p, tmp_path) == (False, "could not fetch commit or tag")
    assert not (tmp_path / p.slug).exists()


def test_prefilter_keeps_indirect_sinks():
    """Sinks that never name ProcessBuilder or ScriptEngine: Jenkins launchers,
    YAML/object deserialization, JSP output."""
    from auditor.prefilter import keep, drop_reason
    assert keep("new ArgumentListBuilder().add(image)", ["cmdi"])
    assert keep("new Yaml().load(rule)", ["codei"])
    assert keep("new ObjectInputStream(in).readObject()", ["codei"])
    assert keep("out.print(request.getParameter(\"q\"))", ["xss"])
    assert drop_reason("src/main/java/A.java", "int x = 1;", ["cmdi"]) == "no keyword for cmdi"
    assert drop_reason("src/test/java/A.java", "", ["cmdi"]) == "test path"
    assert drop_reason("src/main/java/A.java", "Runtime.getRuntime()", ["cmdi"]) is None


def test_prefilter_check_names_the_reason(tmp_path):
    import json
    from eval.prefilter_check import check
    (tmp_path / "p1/src/main/java").mkdir(parents=True)
    (tmp_path / "p1/src/main/java/A.java").write_text("class A {\n  void f() {\n    x();\n  }\n}\n")
    (tmp_path / "p1/src/main/java/B.java").write_text("class B { Runtime.getRuntime(); }\n")
    labels = [{"file": "p1/src/main/java/A.java", "line": 2, "cve": "CVE-1", "method": "f",
               "bug_class": "cmdi"},
              {"file": "p1/src/main/java/B.java", "line": 1, "cve": "CVE-2", "method": "g",
               "bug_class": "cmdi"}]
    out = check(tmp_path, labels, ["cmdi"])
    assert out.startswith("1 of 2 CVEs") and "CVE-1" in out and "CVE-2" not in out
    assert "no keyword for cmdi" in out and "void f()" in out


def test_screen_stance_changes_only_the_reporting_bar():
    from auditor.prompts import system_prompt
    precise = system_prompt(["cmdi"], True, False)
    screen = system_prompt(["cmdi"], True, False, stance="screen")
    assert "Precision matters more than recall" in precise
    assert "SCREENING pass" in screen and "Precision matters more" not in screen
    from auditor.config import AuditConfig
    assert AuditConfig(stance="screen").cell().endswith("-screen")
    assert AuditConfig().cell() == "explore-sa"


def test_label_paths_follow_package_renames(tmp_path):
    """CVE-2021-30181: the fix commit is under org/apache/dubbo but the
    vulnerable 2.6.8 source is under com/alibaba/dubbo. The label must point at
    the file that was actually audited, or a real hit scores as a miss."""
    from benchmarks.cwe_bench_java import resolve_label_paths
    real = tmp_path / "dubbo/dubbo-cluster/src/main/java/com/alibaba/dubbo/rpc/cluster/router/script"
    real.mkdir(parents=True)
    (real / "ScriptRouter.java").write_text("class ScriptRouter {}\n")
    other = tmp_path / "dubbo/dubbo-other/src/main/java/x"
    other.mkdir(parents=True)
    (other / "ScriptRouter.java").write_text("class ScriptRouter {}\n")
    fix = "dubbo/dubbo-cluster/src/main/java/org/apache/dubbo/rpc/cluster/router/script/ScriptRouter.java"
    labels = [{"file": fix, "cve": "CVE-2021-30181"},
              {"file": "dubbo/gone/Missing.java", "cve": "CVE-X"}]
    notes = resolve_label_paths(tmp_path, labels)
    assert labels[0]["file"] == ("dubbo/dubbo-cluster/src/main/java/com/alibaba/dubbo/rpc/"
                                 "cluster/router/script/ScriptRouter.java")
    assert labels[0]["fix_file"] == fix
    assert labels[1]["file"] == "dubbo/gone/Missing.java" and "left as is" in notes[1]


def test_prefilter_keeps_hand_built_html():
    """CVE-2019-10078: a JSPWiki plugin builds links by string concatenation."""
    from auditor.prefilter import keep
    assert keep('sb.append("<a href=\\"" + url + "\\">" + name + "</a>");', ["xss"])


def test_prefilter_ignores_reflection_and_serializable_hooks():
    from auditor.prefilter import keep
    assert not keep("m.getParameterTypes(); m.getParameters();", ["xss"])
    assert not keep("private void readObject(ObjectInputStream s)", ["xss"])
    assert keep("Object o = in.readObject();", ["codei"])
    assert keep("String q = req.getParameter(\"q\");", ["xss"])


def test_keyword_stats_counts_sole_keepers(tmp_path):
    from eval.prefilter_check import keyword_stats
    (tmp_path / "p/src").mkdir(parents=True)
    (tmp_path / "p/src/A.java").write_text("new ProcessBuilder(x)")
    (tmp_path / "p/src/B.java").write_text("new ProcessBuilder(x); Runtime.getRuntime()")
    out = keyword_stats(tmp_path, [{"file": "p/src/A.java", "cve": "C1"}], ["cmdi"])
    assert "2 files kept" in out and "| `ProcessBuilder` | 1 | 2 |" in out
    assert "- C1: ProcessBuilder" in out
