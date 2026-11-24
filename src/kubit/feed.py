"""Versioned compatibility evidence feed contracts.

The runtime does not consume this format yet.  This module defines the stable
v1 encoding and validation boundary used by later builder and reader changes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class FeedValidationError(ValueError):
    """Raised when a feed cannot be safely persisted or consumed."""


def canonical_json(value: Any) -> bytes:
    """Return Kubit's deterministic UTF-8 JSON encoding.

    Feed JSON is restricted to objects, arrays, strings, integers, booleans,
    and null.  Floats are rejected so their cross-language representation can
    never change a revision digest.
    """

    _validate_json_value(value, "$")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def normalize_feed(feed: dict[str, Any]) -> dict[str, Any]:
    """Copy a feed and normalize the two explicitly unordered collections."""

    normalized = copy.deepcopy(feed)
    providers = normalized.get("providers")
    if isinstance(providers, list):
        for provider in providers:
            if isinstance(provider, dict) and isinstance(provider.get("rules"), list):
                provider["rules"].sort(key=lambda rule: rule.get("id", "") if isinstance(rule, dict) else "")
        providers.sort(key=lambda provider: provider.get("name", "") if isinstance(provider, dict) else "")
    return normalized


def compute_feed_revision(feed: dict[str, Any]) -> str:
    """Compute the revision over a normalized envelope without its revision."""

    payload = normalize_feed(feed)
    payload.pop("feed_revision", None)
    return f"sha256:{hashlib.sha256(canonical_json(payload)).hexdigest()}"


def finalize_feed(feed: dict[str, Any]) -> dict[str, Any]:
    """Normalize, assign, and validate an immutable feed revision."""

    finalized = normalize_feed(feed)
    finalized["feed_revision"] = compute_feed_revision(finalized)
    validate_feed(finalized)
    return finalized


def validate_feed(feed: dict[str, Any]) -> None:
    """Validate the v1 structural and security-critical semantic contract."""

    if not isinstance(feed, dict):
        raise FeedValidationError("feed must be an object")
    expected = {"schema_version", "feed_revision", "generated_at", "expires_at", "providers"}
    _require_keys(feed, expected, expected, "feed")
    if feed["schema_version"] != SCHEMA_VERSION:
        raise FeedValidationError(f"unsupported schema_version: {feed['schema_version']!r}")
    if not isinstance(feed["feed_revision"], str) or not _REVISION.fullmatch(feed["feed_revision"]):
        raise FeedValidationError("feed_revision must be a lowercase sha256 digest")

    generated = _timestamp(feed["generated_at"], "generated_at")
    expires = _timestamp(feed["expires_at"], "expires_at")
    if expires <= generated:
        raise FeedValidationError("expires_at must be later than generated_at")

    providers = feed["providers"]
    if not isinstance(providers, list):
        raise FeedValidationError("providers must be an array")
    provider_names: set[str] = set()
    rule_ids: set[str] = set()
    for index, provider in enumerate(providers):
        path = f"providers[{index}]"
        if not isinstance(provider, dict):
            raise FeedValidationError(f"{path} must be an object")
        required = {"name", "parser_version", "retrieved_at", "source", "rules"}
        _require_keys(provider, required, required, path)
        name = _nonempty(provider["name"], f"{path}.name")
        if name in provider_names:
            raise FeedValidationError(f"duplicate provider name: {name}")
        provider_names.add(name)
        _nonempty(provider["parser_version"], f"{path}.parser_version")
        if _timestamp(provider["retrieved_at"], f"{path}.retrieved_at") > generated:
            raise FeedValidationError(f"{path}.retrieved_at must not be later than generated_at")
        _validate_source(provider["source"], f"{path}.source")

        rules = provider["rules"]
        if not isinstance(rules, list) or not rules:
            raise FeedValidationError(f"{path}.rules must be a non-empty array")
        for rule_index, rule in enumerate(rules):
            rule_path = f"{path}.rules[{rule_index}]"
            if not isinstance(rule, dict):
                raise FeedValidationError(f"{rule_path} must be an object")
            _require_keys(rule, {"id", "type", "evidence"}, None, rule_path)
            rule_id = _nonempty(rule["id"], f"{rule_path}.id")
            if rule_id in rule_ids:
                raise FeedValidationError(f"duplicate rule id: {rule_id}")
            rule_ids.add(rule_id)
            _nonempty(rule["type"], f"{rule_path}.type")
            _https_url(rule["evidence"], f"{rule_path}.evidence")

    expected_revision = compute_feed_revision(feed)
    if feed["feed_revision"] != expected_revision:
        raise FeedValidationError(
            f"feed_revision mismatch: expected {expected_revision}, got {feed['feed_revision']}"
        )
    canonical_json(normalize_feed(feed))


def _validate_source(source: Any, path: str) -> None:
    if not isinstance(source, dict):
        raise FeedValidationError(f"{path} must be an object")
    required = {"requested_url", "resolved_url", "media_type", "sha256"}
    allowed = required | {"revision", "etag", "last_modified"}
    _require_keys(source, required, allowed, path)
    _https_url(source["requested_url"], f"{path}.requested_url")
    _https_url(source["resolved_url"], f"{path}.resolved_url")
    _nonempty(source["media_type"], f"{path}.media_type")
    if not isinstance(source["sha256"], str) or not _DIGEST.fullmatch(source["sha256"]):
        raise FeedValidationError(f"{path}.sha256 must be a lowercase SHA-256 digest")
    for optional in ("revision", "etag", "last_modified"):
        if optional in source:
            _nonempty(source[optional], f"{path}.{optional}")


def _require_keys(value: dict[str, Any], required: set[str], allowed: set[str] | None, path: str) -> None:
    missing = sorted(required - value.keys())
    if missing:
        raise FeedValidationError(f"{path} is missing required fields: {', '.join(missing)}")
    if allowed is not None:
        unexpected = sorted(value.keys() - allowed)
        if unexpected:
            raise FeedValidationError(f"{path} contains unexpected fields: {', '.join(unexpected)}")


def _nonempty(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise FeedValidationError(f"{path} must be a non-empty string")
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise FeedValidationError(f"{path} must be an RFC 3339 UTC timestamp with second precision")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise FeedValidationError(f"{path} is not a valid timestamp") from error


def _https_url(value: Any, path: str) -> str:
    value = _nonempty(value, path)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise FeedValidationError(f"{path} must use HTTPS without credentials or fragments")
    return value


def _validate_json_value(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise FeedValidationError(f"{path} contains a non-string object key")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise FeedValidationError(f"{path} contains unsupported JSON value {type(value).__name__}")
