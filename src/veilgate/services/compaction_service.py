"""Payload compaction, Markdown table rendering, and schema relaxation service."""

from typing import Any

from veilgate.config.policy_models import CompactionSpec


class CompactionService:
    """Renders compact representations, truncates large arrays, and relaxes schemas."""

    def __init__(self, compaction_spec: CompactionSpec) -> None:
        self.spec: CompactionSpec = compaction_spec

    def render_markdown_table(self, items: list[dict[str, Any]]) -> str:
        """Render a list of homogeneous dictionaries as a compact Markdown table."""
        if not items:
            return ""

        # Extract union of keys preserving first occurrence order
        headers: list[str] = []
        for item in items:
            for k in item.keys():
                if k not in headers:
                    headers.append(k)

        if not headers:
            return ""

        header_row = "| " + " | ".join(headers) + " |"
        sep_row = "| " + " | ".join(["---"] * len(headers)) + " |"
        data_rows: list[str] = []

        for item in items:
            row_vals = [str(item.get(h, "")).replace("\n", " ").replace("|", "\\|") for h in headers]
            data_rows.append("| " + " | ".join(row_vals) + " |")

        return "\n".join([header_row, sep_row] + data_rows)

    def compact_array_payload(
        self,
        items: list[Any],
        stash_id: str | None = None,
    ) -> tuple[list[Any], bool]:
        """Truncate array if length exceeds max_array_items threshold.

        Returns:
            Tuple of (compacted_items, was_truncated).
        """
        max_items = self.spec.max_array_items
        if len(items) <= max_items:
            return items, False

        kept = items[:max_items]
        remaining = len(items) - max_items
        truncation_note = {
            "_note": f"Truncated {remaining} items exceeding max limit of {max_items}.",
            "stash_id": stash_id or "",
            "hint": f"Call veilgate_expand(stash_id='{stash_id}') to view full collection.",
        }
        kept.append(truncation_note)
        return kept, True

    def compact_string(
        self,
        text: str,
        stash_id: str | None = None,
    ) -> tuple[str, bool]:
        """Truncate oversized string if character length exceeds max_string_chars threshold.

        Returns:
            Tuple of (compacted_text, was_truncated).
        """
        max_chars = self.spec.max_string_chars
        if len(text) <= max_chars:
            return text, False

        kept = text[:max_chars]
        remaining = len(text) - max_chars
        resolved_stash = stash_id or ""
        note = (
            f"\n[...truncated {remaining} chars exceeding max limit of {max_chars}. "
            f"Call veilgate_expand(stash_id='{resolved_stash}') to view full text.]"
        )
        return kept + note, True

    def relax_output_schema_for_tokens(
        self,
        schema: dict[str, Any] | None,
        tokenized_properties: list[str],
    ) -> dict[str, Any]:
        """Relax outputSchema types for fields containing token strings (Attack A15 defense).

        Ensures that if an integer/number property is tokenized to '<vg:...>', typed
        MCP clients do not throw schema validation errors by converting type to ['integer', 'string'].
        """
        if not schema or not isinstance(schema, dict) or "properties" not in schema:
            return schema or {}

        relaxed = dict(schema)
        props = dict(relaxed.get("properties", {}))

        for prop_name in tokenized_properties:
            if prop_name in props and isinstance(props[prop_name], dict):
                prop_spec = dict(props[prop_name])
                curr_type = prop_spec.get("type")
                if curr_type in ("integer", "number"):
                    prop_spec["type"] = [curr_type, "string"]
                props[prop_name] = prop_spec

        relaxed["properties"] = props
        return relaxed
