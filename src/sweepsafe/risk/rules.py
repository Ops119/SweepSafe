"""Load and validate the shared ``rules.json`` (single source of truth for Python and JS)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class RuleSpec(BaseModel):
    weight: int = Field(ge=0, le=100)
    message: str


class Level(BaseModel):
    name: str
    min: int = Field(ge=0, le=100)


class ExplainTemplates(BaseModel):
    headline: str
    risk_line: str
    no_findings: str
    advice: dict[str, str]


class Rules(BaseModel):
    version: int
    unlimited_threshold: int
    stale_days: int = Field(ge=0)
    rules: dict[str, RuleSpec]
    levels: list[Level]
    explain: ExplainTemplates

    @field_validator("unlimited_threshold", mode="before")
    @classmethod
    def _parse_threshold(cls, value: object) -> int:
        # Stored as a decimal string so JavaScript can parse it with BigInt.
        if isinstance(value, str):
            return int(value)
        if isinstance(value, int):
            return value
        raise ValueError("unlimited_threshold must be a decimal string")

    @field_validator("levels")
    @classmethod
    def _levels_valid(cls, levels: list[Level]) -> list[Level]:
        if not levels:
            raise ValueError("at least one level is required")
        ordered = sorted(levels, key=lambda lv: lv.min, reverse=True)
        if ordered[-1].min != 0:
            raise ValueError("the lowest level must start at 0")
        return ordered

    def level_for(self, score: int) -> str:
        for level in self.levels:  # sorted high -> low
            if score >= level.min:
                return level.name
        return self.levels[-1].name


def parse_rules(text: str) -> Rules:
    return Rules.model_validate(json.loads(text))


@lru_cache(maxsize=1)
def default_rules() -> Rules:
    text = (resources.files("sweepsafe") / "data" / "rules.json").read_text(encoding="utf-8")
    return parse_rules(text)


def load_rules(path: str | Path | None = None) -> Rules:
    """Load rules from ``path`` or fall back to the packaged defaults."""
    if path is None:
        return default_rules()
    return parse_rules(Path(path).read_text(encoding="utf-8"))
