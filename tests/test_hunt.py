"""hunt.py: screen -> triage (rank, never drop) -> deep dive, offline."""
import json

from auditor.budget import Budget
from auditor.hunt import HUNT_THREAT, HuntConfig, estimate, hunt_units, run_hunt
from auditor.prompts import threat_text
from auditor.tools import Workspace
from tests.conftest import FakeBackend, reply, report

FILES = ("class Files {\n"
         "  void serve(String name) {\n"
         "    java.io.File f = new java.io.File(base, name);\n"
         "  }\n"
         "}\n")
UPLOAD = ("class Upload {\n"
          "  void save() {\n"
          "    new java.io.FileInputStream(\"/etc/app.conf\");\n"
          "  }\n"
          "}\n")


def _repo(tmp_path):
    src = tmp_path / "proj" / "src" / "main" / "java"
    src.mkdir(parents=True)
    (src / "Files.java").write_text(FILES)
    (src / "Upload.java").write_text(UPLOAD)
    (src / "Math.java").write_text("class Math { int add(int a, int b) { return a + b; } }\n")
    test = tmp_path / "proj" / "src" / "test" / "java"
    test.mkdir(parents=True)
    (test / "FilesTest.java").write_text("class FilesTest { void t() { new java.io.File(\"x\"); } }\n")
    return tmp_path / "proj"


def _models():
    def screen(conv):
        target = conv.sent[0][1].split("Audit target: ")[1].split(".\n")[0]
        return report([{"bug_class": "path", "file": target, "line": 3, "cwe": "CWE-22",
                        "confidence": 0.5, "path": "name -> new File"}])

    def triage(conv):
        p = conv.sent[0][1]
        if "Files.java" in p:
            v = {"score": 0.9, "attacker": "caller of a public API", "reason": "no check",
                 "path_steps": [{"file": "src/main/java/Files.java", "line": 3,
                                 "quote": "new java.io.File(base, name)"}]}
        else:
            v = {"score": 0.1, "attacker": "nobody", "reason": "constant path",
                 "path_steps": [{"file": "src/main/java/Upload.java", "line": 3,
                                 "quote": "not in the file"}]}
        return reply(json.dumps(v), stop="end_turn")

    def deep(conv):
        if len(conv.sent) == 1:
            return reply(calls=[("g1", "grep", {"pattern": "serve\\("})])
        assert conv.sent[-1][0] == "tool_results"
        return reply(calls=[("v1", "report_verdict", {
            "verdict": "confirmed", "score": 0.8, "title": "Traversal in Files.serve",
            "attacker": "caller of a public API", "poc": "../../etc/passwd",
            "reproduce": "call serve(\"../../etc/passwd\") in a test app", "reason": "no check",
            "path_steps": [{"file": "src/main/java/Files.java", "line": 3,
                            "quote": "new java.io.File(base, name)"}]})])

    b = {"claude-sonnet-5-5": FakeBackend(screen, model="claude-sonnet-5-5"),
         "claude-haiku-5-5": FakeBackend(triage, model="claude-haiku-5-5"),
         "claude-opus-5-5": FakeBackend(deep, model="claude-opus-5-5")}
    return b, (lambda model, effort=None: b[model])


# min_score 0.2 here so the test can check a low-scored flag is ranked but not
# deep-dived; the shipped default is 0.0 (deep_top alone caps the dive).
HC = HuntConfig(bug_classes=("path",), triage_model="claude-haiku-5-5", workers=1,
                min_score=0.2)


def test_default_min_score_lets_triage_rank_without_vetoing():
    assert HuntConfig().min_score == 0.0


def test_units_skip_tests_and_files_with_no_relevant_api(tmp_path):
    units, stats = hunt_units(Workspace(str(_repo(tmp_path))), ["path"])
    assert sorted(u.id for u in units) == ["src/main/java/Files.java",
                                           "src/main/java/Upload.java"]
    assert stats == {"files": 4, "tests": 1, "non_product": 0, "no_keyword": 1, "kept": 2}
    assert estimate(2, HC)["screen"] > 0


def test_hunt_ranks_everything_and_deep_dives_the_top(tmp_path):
    repo, out = _repo(tmp_path), tmp_path / "out"
    b, make = _models()
    path = run_hunt(str(repo), out, HC, Budget(None), make, log=lambda m: None)

    system = b["claude-sonnet-5-5"].conversations[0].system
    assert HUNT_THREAT in system and threat_text("remote") not in system
    # the low scorer stays in the report (ranked, not dropped) but gets no deep dive
    assert b["claude-haiku-5-5"].calls == 2 and b["claude-opus-5-5"].calls == 2
    text = path.read_text(encoding="utf-8")
    assert "### 1. Traversal in Files.serve (confirmed, score 0.8)" in text
    assert "Quotes verified: 100%" in text and "../../etc/passwd" in text
    other = text.split("## Other flags")[1]
    assert "Upload.java:3" in other and "| 0.05 |" in other   # 0.1 cut in half: bad quote

    calls = {m: x.calls for m, x in b.items()}
    run_hunt(str(repo), out, HC, Budget(None), make, log=lambda m: None)
    assert {m: x.calls for m, x in b.items()} == calls          # rerun pays for nothing
    found = json.loads((out / "findings.json").read_text())
    assert found["costs"]["total"] > 0 and len(found["ranked"]) == 2


def test_budget_cap_stops_new_work_and_a_rerun_finishes(tmp_path):
    repo, out = _repo(tmp_path), tmp_path / "out"
    b, make = _models()
    run_hunt(str(repo), out, HC, Budget(1e-9), make, log=lambda m: None)
    assert b["claude-sonnet-5-5"].calls == 1 and b["claude-opus-5-5"].calls == 0
    assert "not reached" in (out / "report.md").read_text(encoding="utf-8")
    run_hunt(str(repo), out, HC, Budget(None), make, log=lambda m: None)
    assert b["claude-sonnet-5-5"].calls == 2 and b["claude-opus-5-5"].calls == 2
