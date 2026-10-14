"""Shared fixtures: a scripted fake model backend and a tiny Juliet-style repo."""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.llm import Reply, ToolCall  # noqa: E402

JULIET_FILE = """\
package testcases.CWE78_OS_Command_Injection;

import java.io.*;

public class CWE78_OS_Command_Injection__Environment_01 extends AbstractTestCase
{
    public void bad() throws Throwable
    {
        String data;
        /* POTENTIAL FLAW: Read data from an environment variable */
        data = System.getenv("ADD");
        String osCommand = "/bin/ls ";
        /* POTENTIAL FLAW: command injection */
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();
    }

    public void good() throws Throwable
    {
        goodG2B();
    }

    /* goodG2B() - uses goodsource and badsink */
    private void goodG2B() throws Throwable
    {
        String data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        String osCommand = "/bin/ls ";
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();
    }

    public static void main(String[] args) throws Exception
    {
        mainFromParent(args);
    }
}
"""
# bad sink on line 14, good-side twin sink on line 30, main() on lines 34-37


class FakeConversation:
    def __init__(self, backend, system, tools):
        self.backend, self.system, self.tools = backend, system, tools
        self.sent: list = []

    def user(self, text):
        self.sent.append(("user", text))

    def tool_results(self, results, note=None):
        self.sent.append(("tool_results", results, note))

    def step(self, max_tokens):
        self.backend.calls += 1
        script = self.backend.script
        r = script(self) if callable(script) else script.pop(0)
        return r


class FakeBackend:
    """script: list of Replies consumed in order, or fn(conversation) -> Reply."""
    def __init__(self, script, model="claude-opus-5-5"):
        self.script, self.model, self.calls = script, model, 0
        self.conversations: list[FakeConversation] = []

    def conversation(self, system, tools, cache=False):
        c = FakeConversation(self, system, tools)
        self.conversations.append(c)
        return c


def reply(text="", calls=(), stop="tool_use", usage=None):
    return Reply(text, [ToolCall(*c) for c in calls], stop,
                 usage or {"input": 100, "output": 20, "cache_read": 0, "cache_write": 0})


def report(findings, cid="r1"):
    return reply(calls=[(cid, "report_findings", {"findings": findings})])


@pytest.fixture
def juliet_repo(tmp_path):
    d = tmp_path / "juliet"
    d.mkdir()
    (d / "CWE78_OS_Command_Injection__Environment_01.java").write_text(JULIET_FILE)
    labels = [{"file": "CWE78_OS_Command_Injection__Environment_01.java",
               "line": 14, "bug_class": "cmdi"}]
    return d, labels


@pytest.fixture
def toy_repo():
    root = Path(__file__).resolve().parent.parent / "benchmarks" / "toy"
    import json
    return root, json.loads((root / "labels.json").read_text())
