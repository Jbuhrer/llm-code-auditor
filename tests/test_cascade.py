"""Verifier pilot (--verify-sample) and Message Batches (--batch), offline."""
import json
import sys
from types import SimpleNamespace as NS

import eval.experiment as ex
from auditor.batch import run_batch
from auditor.llm import AnthropicBackend
from eval.pilot import summarize
from tests.conftest import FakeBackend, report


def _message(verdict="confirmed"):
    return NS(content=[NS(type="text", text=json.dumps({"verdict": verdict}))],
              stop_reason="end_turn",
              usage=NS(input_tokens=1000, output_tokens=100, cache_read_input_tokens=0,
                       cache_creation_input_tokens=0))


class FakeBatches:
    """Confirms flags in a.py, rejects the rest; ends after `polls` retrieves."""
    def __init__(self, polls=0, error_ids=()):
        self.created, self.polls, self.error_ids = [], polls, set(error_ids)

    def create(self, requests):
        self.created.append(requests)
        return NS(id=f"batch_{len(self.created)}")

    def retrieve(self, bid):
        self.polls -= 1
        return NS(processing_status="ended" if self.polls < 0 else "in_progress",
                  request_counts=NS(processing=1, succeeded=0, errored=0))

    def results(self, bid):
        for r in self.created[-1]:
            if r["custom_id"] in self.error_ids:
                yield NS(custom_id=r["custom_id"], result=NS(
                    type="errored", error=NS(type="error", error=NS(
                        type="overloaded_error", message="busy"))))
                continue
            text = r["params"]["messages"][0]["content"]
            ok = '"file": "a.py"' in text
            yield NS(custom_id=r["custom_id"],
                     result=NS(type="succeeded", message=_message(
                         "confirmed" if ok else "rejected")))


def _backend(batches):
    return AnthropicBackend("claude-sonnet-5-5", effort="medium",
                            client=NS(messages=NS(batches=batches)))


def test_run_batch_resumes_without_resubmitting(tmp_path):
    batches = FakeBatches(polls=1)
    state = tmp_path / "x.batch.json"
    b = _backend(batches)
    out = run_batch(b, {"f0": "hi"}, 100, state, log=lambda m: None, sleep=lambda s: None)
    assert out["f0"].stop_reason == "end_turn" and out["f0"].usage["input"] == 1000
    req = batches.created[0][0]["params"]
    assert req["output_config"] == {"effort": "medium"} and req["model"] == "claude-sonnet-5-5"
    assert not state.exists()

    state.write_text(json.dumps({"batch_id": "batch_1", "ids": ["f0"]}))  # interrupted run
    run_batch(b, {"f0": "hi"}, 100, state, log=lambda m: None, sleep=lambda s: None)
    assert len(batches.created) == 1   # picked the old batch back up, didn't pay twice


def test_batch_errors_come_back_as_strings(tmp_path):
    out = run_batch(_backend(FakeBatches(error_ids={"f1"})), {"f0": "a", "f1": "b"}, 100,
                    tmp_path / "s.json", log=lambda m: None)
    assert out["f1"].startswith("BatchError: overloaded_error")


def _setup(tmp_path, monkeypatch, batches):
    repo = tmp_path / "repo"
    repo.mkdir()
    for n in ("a", "b", "c", "d"):
        (repo / f"{n}.py").write_text("x = 1\n")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps([{"file": "a.py", "line": 1, "bug_class": "sqli"}]))
    audits = []

    def backend(model, *_a, **_k):
        if model == "claude-sonnet-5-5":
            return _backend(batches)

        def script(conv):
            audits.append(1)
            name = conv.sent[0][1].split("=== ")[1].split(" ")[0]
            return report([{"bug_class": "sqli", "file": name, "line": 1, "cwe": "CWE-89",
                            "confidence": 0.9}])
        return FakeBackend(script, model=model)

    monkeypatch.setattr(ex, "make_backend", backend)
    base = ["experiment.py", str(repo), str(labels), "--configs", "C0", "--runs", "1",
            "--unit", "file", "--no-baseline", "--workers", "1", "--skip-preflight",
            "--models", "claude-haiku-5-5", "--out", str(tmp_path / "res")]
    return base, audits


def test_pilot_sample_through_a_batch(tmp_path, monkeypatch):
    batches = FakeBatches()
    base, audits = _setup(tmp_path, monkeypatch, batches)
    monkeypatch.setattr(sys, "argv", base)
    ex.main()                                   # the Haiku screen, 4 flags, 1 on a label
    assert len(audits) == 4

    cascade = ["--verifier-model", "claude-sonnet-5-5", "--validation", "plain",
               "--verify-sample", "2", "--batch"]
    monkeypatch.setattr(sys, "argv", base + cascade)
    ex.main()
    assert len(audits) == 4                     # the screen wasn't paid for again
    run = tmp_path / "res" / "claude-haiku-5-5" / "fixed-nosa" / "run1"
    pilot = json.loads((run / "pilot2-val-plain@claude-sonnet-5-5.json").read_text())
    assert len(pilot["records"]) == 2 and len(batches.created[0]) == 2
    files = sorted(json.loads((run / "audit.json").read_text())["units"][i]["findings"][0]
                   ["file"] for i in pilot["indices"])
    assert files[0] == "a.py"                   # the labelled bug is always in the sample
    assert all(r["price_mult"] == 0.5 for r in pilot["records"])
    # 2 calls x (1000 in, 100 out) on Sonnet at half price
    assert pilot["cost_usd"] == round(2 * (1000 * 2 + 100 * 10) / 1e6 * 0.5, 6)
    assert not list(run.glob("val-*.json"))     # a pilot never shows up as a report cell

    s = summarize(tmp_path / "res")
    assert "| 1/1 | 1/1 |" in s and "for 4 flags" in s

    monkeypatch.setattr(sys, "argv", base + cascade)
    ex.main()
    assert len(batches.created) == 1            # finished pilot isn't resubmitted


def test_errored_batch_requests_are_retried(tmp_path, monkeypatch):
    batches = FakeBatches(error_ids={"f0"})
    base, _ = _setup(tmp_path, monkeypatch, batches)
    monkeypatch.setattr(sys, "argv", base)
    ex.main()
    cascade = ["--verifier-model", "claude-sonnet-5-5", "--validation", "plain", "--batch"]
    monkeypatch.setattr(sys, "argv", base + cascade)
    ex.main()
    run = tmp_path / "res" / "claude-haiku-5-5" / "fixed-nosa" / "run1"
    v = json.loads((run / "val-plain@claude-sonnet-5-5.json").read_text())
    assert v["records"][0]["error"] and len(batches.created[-1]) == 4

    batches.error_ids = set()
    ex.main()
    assert [r["custom_id"] for r in batches.created[-1]] == ["f0"]   # only the failed one
    v = json.loads((run / "val-plain@claude-sonnet-5-5.json").read_text())
    assert not any(r["error"] for r in v["records"])


def test_report_lists_cves_the_validator_lost(tmp_path, monkeypatch, capsys):
    """Real-CVE runs: the report names each CVE the validator dropped, with the
    rejected flag and the validator's reason."""
    import eval.report as rp
    from tests.test_cwe_bench_java import _project_repo
    repo, labels = _project_repo(tmp_path)
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(labels))
    batches = FakeBatches()
    batches.results = lambda bid: (NS(custom_id=r["custom_id"], result=NS(
        type="succeeded", message=NS(
            content=[NS(type="text", text=json.dumps(
                {"verdict": "rejected", "reason": "name is checked upstream"}))],
            stop_reason="end_turn", usage=_message().usage)))
        for r in batches.created[-1])

    def backend(model, *_a, **_k):
        if model == "claude-sonnet-5-5":
            return _backend(batches)
        return FakeBackend(lambda conv: report([{"bug_class": "path", "line": 3,
                                                 "file": "src/main/java/Files.java",
                                                 "cwe": "CWE-22", "confidence": 0.9}]),
                           model=model)

    monkeypatch.setattr(ex, "make_backend", backend)
    out = tmp_path / "res"
    monkeypatch.setattr(sys, "argv", [
        "experiment.py", str(repo), str(lp), "--configs", "C0", "--runs", "1",
        "--bugs", "path", "--no-baseline", "--workers", "1", "--skip-preflight",
        "--models", "claude-haiku-5-5", "--verifier-model", "claude-sonnet-5-5",
        "--validation", "plain", "--batch", "--out", str(out)])
    ex.main()
    monkeypatch.setattr(sys, "argv", ["report.py", str(out), "--boot", "50"])
    capsys.readouterr()
    rp.main()
    text = capsys.readouterr().out
    assert "CVEs the validator lost" in text
    assert "| CVE-2021-9 |" in text and "name is checked upstream" in text
