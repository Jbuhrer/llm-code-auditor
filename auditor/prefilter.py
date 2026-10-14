"""
Label-free file pre-filter for big repos.

Keeps a file only if it mentions an API relevant to the bug classes being hunted,
and drops test code. It never reads ground truth and is applied identically to
every config, so comparisons stay fair; its recall (did it keep the labelled
file?) is reported separately so its effect is visible.
"""
from __future__ import annotations
import re

KEYWORDS = {
    "path": ["java.io.File", "new File(", "Paths.get(", "Path.of(", "FileInputStream",
             "FileOutputStream", "FileReader", "FileWriter", "ZipEntry", "ZipFile",
             "getResource", ".resolve(", "Files."],
    "cmdi": ["Runtime.getRuntime", "ProcessBuilder", ".exec(", "Commandline", "CommandLine"],
    "xss": ["HttpServletResponse", "getWriter(", "PrintWriter", "ResponseBody", "html",
            "Html", "escape", "Escape", "sanitize", "Sanitize", "Policy"],
    "codei": ["ScriptEngine", "ExpressionParser", "Expression", "Ognl", "OGNL",
              "ELProcessor", "ValueStack", "Class.forName", "defineClass", "MVEL",
              "Velocity", "freemarker", "Freemarker", "groovy", "Groovy", "eval("],
}
TEST_PATH = re.compile(r"(^|/)(src/test|test|tests|testing|it)/|Test[s]?\.java$")


# demo apps, samples and docs ship in the repo but aren't the library the CVE is
# in; auditing them costs money and only adds off-target findings
NON_PRODUCT = re.compile(r"(^|/)(docs?|samples?|examples?|showcase|demos?|apps/showcase)/"
                         r"|\.min\.js$")


def is_test(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def is_non_product(path: str) -> bool:
    return bool(NON_PRODUCT.search(path)) or "-sample" in path or "-example" in path


def keep(text: str, classes: list[str]) -> bool:
    """True if the file text mentions any keyword for any of the classes.
    Unknown or 'all' classes keep everything."""
    words = [w for c in classes for w in KEYWORDS.get(c, [])]
    if not words or any(c not in KEYWORDS for c in classes):
        return True
    return any(w in text for w in words)
