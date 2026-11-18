"""Pure policy checks: prompt-injection detection, request rules and response validation.

Violations are reported as short codes that never contain request or response content.
"""

import json
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import jsonschema

from app.models.policy import Policy
from app.schemas.llm import LLMParameters
from app.schemas.policy import (
    ContentSecurityDefinition,
    PromptInjectionDefinition,
    RequestRuleDefinition,
    ResponseSchemaDefinition,
)

_STRIPPED_CATEGORIES = frozenset({"Mn", "Cf"})
_FLAGS = re.IGNORECASE | re.DOTALL


@dataclass(frozen=True, slots=True)
class CompiledRule:
    id: str
    regex: re.Pattern[str]


def compile_rule(rule_id: str, pattern: str) -> CompiledRule:
    return CompiledRule(rule_id, re.compile(pattern, _FLAGS))


_OVERRIDE_VERB = r"(?:ignore|disregard|forget|override|bypass|discard|skip)"
_INSTRUCTION_NOUN = r"(?:instructions?|prompts?|rules?|directives?|guidelines?|context|programming)"

# Always applied, independent of stored policies, so protection holds on a fresh install.
BUILTIN_INJECTION_RULES: tuple[CompiledRule, ...] = (
    compile_rule(
        "builtin.ignore_instructions",
        rf"\b{_OVERRIDE_VERB}\b.{{0,40}}\b(?:previous|prior|above|earlier|all|any|your|the|these|"
        rf"those|system)\b.{{0,40}}\b{_INSTRUCTION_NOUN}\b",
    ),
    compile_rule(
        "builtin.reveal_system_prompt",
        r"\b(?:reveal|show|print|display|repeat|output|leak|disclose|tell me)\b.{0,40}"
        r"\b(?:system|hidden|initial|original|developer|secret)\b.{0,20}"
        r"\b(?:prompt|instructions?|message)\b",
    ),
    compile_rule(
        "builtin.role_override",
        r"\b(?:you are now|from now on,? you|pretend (?:to be|you are)|act as|roleplay as)\b"
        r".{0,60}\b(?:unrestricted|unfiltered|jailbroken|dan|developer mode|"
        r"no (?:rules|restrictions|limits))\b",
    ),
    compile_rule(
        "builtin.jailbreak_terms",
        r"\b(?:jailbreak(?:ing|ed)?|dan mode|developer mode|do anything now)\b",
    ),
    compile_rule(
        "builtin.disable_safety",
        r"\b(?:disable|turn off|remove|bypass|ignore|circumvent)\b.{0,30}"
        r"\b(?:safety|guardrails?|filters?|restrictions?|content polic(?:y|ies)|moderation)\b",
    ),
    compile_rule(
        "builtin.delimiter_injection",
        r"(?:<\|?\s*(?:system|im_start|im_end|endoftext)\s*\|?>|\[/?inst\]|"
        r"#{2,}\s*(?:system|instructions?)\b)",
    ),
    compile_rule(
        "builtin.new_instructions",
        r"\b(?:new|updated|real|actual) (?:instructions?|system prompt)\s*:",
    ),
)


def normalize_text(text: str) -> str:
    """Fold case, strip accents and invisible format characters, and collapse whitespace.

    This defeats trivial evasion such as zero-width spaces, homoglyph-free accent tricks and
    spacing, so that rules match what a model would read.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    kept = "".join(ch for ch in decomposed if unicodedata.category(ch) not in _STRIPPED_CATEGORIES)
    return " ".join(kept.casefold().split())


def rules_from_policies(policies: Iterable[Policy]) -> list[CompiledRule]:
    """Compile the patterns of stored prompt-injection policies."""
    compiled: list[CompiledRule] = []
    for policy in policies:
        definition = PromptInjectionDefinition.model_validate(policy.definition)
        compiled.extend(compile_rule(rule.id, rule.pattern) for rule in definition.rules)
    return compiled


def detect_injection(text: str, extra_rules: Sequence[CompiledRule] = ()) -> list[str]:
    """Return the ids of every rule that matches the normalised input."""
    normalized = normalize_text(text)
    return [
        rule.id
        for rule in (*BUILTIN_INJECTION_RULES, *extra_rules)
        if rule.regex.search(normalized) is not None
    ]


def check_request_rules(
    text: str,
    parameters: LLMParameters | None,
    definitions: Iterable[RequestRuleDefinition],
) -> list[str]:
    violations: list[str] = []
    supplied = parameters.model_dump(exclude_none=True) if parameters else {}
    for rule in definitions:
        if rule.min_input_length is not None and len(text) < rule.min_input_length:
            violations.append("input_too_short")
        if rule.max_input_length is not None and len(text) > rule.max_input_length:
            violations.append("input_too_long")
        if rule.allowed_parameters is not None:
            violations.extend(
                f"parameter_not_allowed:{name}"
                for name in sorted(supplied)
                if name not in rule.allowed_parameters
            )
        limit = rule.max_tokens_limit
        if limit is not None and supplied.get("max_tokens", 0) > limit:
            violations.append("max_tokens_exceeded")
    return sorted(set(violations))


def request_rules_from_policies(policies: Iterable[Policy]) -> list[RequestRuleDefinition]:
    return [RequestRuleDefinition.model_validate(policy.definition) for policy in policies]


def validate_response(
    output: str,
    *,
    schemas: Sequence[ResponseSchemaDefinition],
    content_rules: Sequence[ContentSecurityDefinition],
    max_bytes: int,
) -> list[str]:
    """Check provider output against size limits, content rules and JSON Schemas."""
    if not output.strip():
        return ["empty_output"]
    if len(output.encode("utf-8")) > max_bytes:
        return ["output_too_large"]

    violations: list[str] = []
    for rule in content_rules:
        if rule.max_output_chars is not None and len(output) > rule.max_output_chars:
            violations.append("output_too_long")
        for deny in rule.deny_patterns:
            if compile_rule(deny.id, deny.pattern).regex.search(output) is not None:
                violations.append(f"denied_pattern:{deny.id}")
    if schemas:
        violations.extend(_schema_violations(output, schemas))
    return violations


def _schema_violations(output: str, schemas: Sequence[ResponseSchemaDefinition]) -> list[str]:
    try:
        instance = json.loads(output)
    except ValueError:
        return ["output_not_json"]
    violations: list[str] = []
    for definition in schemas:
        validator = jsonschema.Draft202012Validator(definition.json_schema)
        for error in validator.iter_errors(instance):
            path = "/".join(str(part) for part in error.absolute_path) or "$"
            violations.append(f"schema_violation:{path}:{error.validator}")
    return violations


def response_schemas_from_policies(policies: Iterable[Policy]) -> list[ResponseSchemaDefinition]:
    return [ResponseSchemaDefinition.model_validate(policy.definition) for policy in policies]


def content_rules_from_policies(policies: Iterable[Policy]) -> list[ContentSecurityDefinition]:
    return [ContentSecurityDefinition.model_validate(policy.definition) for policy in policies]
