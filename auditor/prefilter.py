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
    "cmdi": ["Runtime.getRuntime", "ProcessBuilder", ".exec(", "Commandline", "CommandLine",
             # Jenkins and commons-exec run processes without ProcessBuilder in sight
             "ArgumentListBuilder", "ProcStarter", ".launch(", "DefaultExecutor"],
    "xss": ["HttpServletResponse", "getWriter(", "PrintWriter", "ResponseBody", "html",
            "Html", "escape", "Escape", "sanitize", "Sanitize", "Policy",
            # exact calls: getParameterTypes() etc. are reflection, everywhere
            "getParameter(", "getParameterValues(", "JspWriter", "sendRedirect(",
            # code that builds HTML by hand (wiki plugins, error pages)
            "href", "<a ", "<li", "<ul", "<div", "<span", "<td", "<table"],
    "codei": ["ScriptEngine", "ExpressionParser", "Expression", "Ognl", "OGNL",
              "ELProcessor", "ValueStack", "Class.forName", "defineClass", "MVEL",
              "Velocity", "freemarker", "Freemarker", "groovy", "Groovy", "eval(",
              # CWE-94 in CWE-Bench-Java also covers deserialization and JNDI RCE
              # .readObject() is a deserialization call; readObject( alone matches
              # every custom Serializable hook
              "Yaml", "ObjectInputStream", ".readObject()", "XStream", "fromXML",
              "parseObject", "Hessian", "InitialContext", "Nashorn"],
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


def drop_reason(inner: str, text: str, classes: list[str],
                exts: tuple[str, ...] = (".java",)) -> str | None:
    """Why build_project_units would skip this file (path relative to its
    project), or None if it is kept. Same order of checks as the unit builder."""
    if not inner.endswith(exts):
        return f"not a {'/'.join(exts)} file"
    if is_test(inner):
        return "test path"
    if is_non_product(inner):
        return "docs/sample/example path"
    if not keep(text, classes):
        return "no keyword for " + "/".join(classes)
    return None
