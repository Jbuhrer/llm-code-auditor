"""
Run configuration: the four thesis factors as toggles, not code edits.

  tool access   static_analysis   semgrep on / off
  exploration   exploration       "explore" (agent navigates the repo with tools)
                                  or "fixed" (context packed up front), both held
                                  to the same context_budget
  validation    validation        evidence stage on / off, plus which evidence
                                  items are required (RO2)
  model         model             any backend model id

Benchmark, prompt structure, and scoring are held constant across cells.

Validation is applied as a post-pass on the SAME raw findings as the matching
no-validation cell, so validation on/off is an exactly paired comparison and the
audit is paid for once.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict, replace

# RO2 evidence requirements. Any subset can be required.
EVIDENCE = {
    "path": "data-flow path reconstruction, each step quoted from the source",
    "sanitizer": "sanitizer identification plus an adequacy judgment",
    "conditions": "path-condition satisfiability reasoning",
    "poc": "a concrete input that traverses the path",
}

DEFAULT_MODEL = "claude-opus-5-5"


@dataclass(frozen=True)
class AuditConfig:
    """Factors that change the audit pass itself (what the model sees and can do)."""
    exploration: str = "explore"          # "explore" | "fixed"
    static_analysis: bool = True
    model: str = DEFAULT_MODEL
    context_budget: int = 24000           # tokens of code context per unit, both modes
    max_turns: int = 15                   # explore mode only
    effort: str | None = "medium"         # Claude effort level, held fixed per run
    temperature: float | None = None      # open-weight backends only
    semgrep_config: str = "auto"
    threat_model: str = "all-external"   # see prompts.THREAT_MODELS
    unit: str = "file"                    # "file" | "testcase" | "repo"
    bug_classes: tuple[str, ...] = ("sqli", "cmdi", "path")
    stance: str = "precise"               # "precise" | "screen", see prompts.STANCES

    def cell(self) -> str:
        """Short, filesystem-safe name for this audit cell."""
        sa = "sa" if self.static_analysis else "nosa"
        return f"{self.exploration}-{sa}" + ("" if self.stance == "precise"
                                             else f"-{self.stance}")

    def as_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ValidationConfig:
    enabled: bool = False
    evidence: tuple[str, ...] = ()        # empty + enabled = plain verdict validator
    window: int = 60                      # fallback: lines either side of the sink
    context_budget: int = 16000           # tokens of the finding's unit shown to the validator
    model: str | None = None              # None = the model that did the audit

    def name(self) -> str:
        if not self.enabled:
            return "noval"
        base = "val-" + ("+".join(self.evidence) if self.evidence else "plain")
        return f"{base}@{self.model.replace(':', '_')}" if self.model else base

    def as_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Preset:
    audit: AuditConfig
    validation: ValidationConfig = field(default_factory=ValidationConfig)


ALL_EVIDENCE = tuple(EVIDENCE)

# The named configurations. C0 is the model-only baseline (the old research.py
# file-by-file setup), C4 is the full agent. Each step adds one component.
PRESETS = {
    "C0": Preset(AuditConfig(exploration="fixed", static_analysis=False)),
    "C1": Preset(AuditConfig(exploration="fixed", static_analysis=True)),
    "C2": Preset(AuditConfig(exploration="explore", static_analysis=False)),
    "C3": Preset(AuditConfig(exploration="explore", static_analysis=True)),
    "C4": Preset(AuditConfig(exploration="explore", static_analysis=True),
                 ValidationConfig(enabled=True, evidence=ALL_EVIDENCE)),
}


def parse_evidence(spec: str) -> tuple[str, ...]:
    """'plain' -> (), 'all' -> every item, 'path+poc' -> ('path', 'poc')."""
    if spec in ("plain", "none", ""):
        return ()
    if spec == "all":
        return ALL_EVIDENCE
    items = tuple(s for s in spec.split("+") if s)
    bad = [s for s in items if s not in EVIDENCE]
    if bad:
        raise ValueError(f"unknown evidence item(s) {bad}; known: {list(EVIDENCE)}")
    return items


def validation_variants(specs: list[str]) -> list[ValidationConfig]:
    """CLI specs like ['off', 'plain', 'all', 'path', 'sanitizer+poc']."""
    out = []
    for s in specs:
        out.append(ValidationConfig() if s == "off"
                   else ValidationConfig(enabled=True, evidence=parse_evidence(s)))
    return out


def full_factorial(base: AuditConfig) -> list[AuditConfig]:
    """Every exploration x static_analysis combination for one model."""
    return [replace(base, exploration=e, static_analysis=s)
            for e in ("fixed", "explore") for s in (False, True)]
