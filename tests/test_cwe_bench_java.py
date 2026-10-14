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
