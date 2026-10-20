"""JSON path traversal, extraction, and update utilities."""

from typing import Any


def parse_path_tokens(path: str) -> list[str]:
    """Parse dotted and bracketed path syntax (e.g. '$.user.items[0].id')."""
    clean = path.lstrip("$.")
    if not clean:
        return []
    tokens: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(clean):
        char = clean[i]
        if char == ".":
            if current:
                tokens.append("".join(current))
                current = []
        elif char == "[":
            if current:
                tokens.append("".join(current))
                current = []
            end = clean.find("]", i)
            if end != -1:
                tokens.append(clean[i + 1 : end])
                i = end
        else:
            current.append(char)
        i += 1
    if current:
        tokens.append("".join(current))
    return tokens


def get_by_path(root: Any, path: str) -> Any:
    """Retrieve value located at the specified JSON path, or None if not found."""
    tokens = parse_path_tokens(path)
    curr = root
    for tok in tokens:
        if isinstance(curr, dict) and tok in curr:
            curr = curr[tok]
        elif isinstance(curr, list) and tok.isdigit():
            idx = int(tok)
            if 0 <= idx < len(curr):
                curr = curr[idx]
            else:
                return None
        else:
            return None
    return curr


def set_by_path(root: dict[str, Any], path: str, value: Any) -> None:
    """Set value at the specified JSON path, mutating the dictionary in-place."""
    tokens = parse_path_tokens(path)
    if not tokens:
        return

    curr: Any = root
    for tok in tokens[:-1]:
        if isinstance(curr, dict):
            if tok not in curr or not isinstance(curr[tok], (dict, list)):
                curr[tok] = {}
            curr = curr[tok]
        else:
            return

    last_tok = tokens[-1]
    if isinstance(curr, dict):
        curr[last_tok] = value


def delete_by_path(root: dict[str, Any], path: str) -> bool:
    """Delete field located at the specified JSON path. Returns True if deleted."""
    tokens = parse_path_tokens(path)
    if not tokens:
        return False

    curr: Any = root
    for tok in tokens[:-1]:
        if isinstance(curr, dict) and tok in curr:
            curr = curr[tok]
        else:
            return False

    last_tok = tokens[-1]
    if isinstance(curr, dict) and last_tok in curr:
        del curr[last_tok]
        return True
    return False


def flatten_paths(data: Any, prefix: str = "$") -> list[tuple[str, Any]]:
    """Recursively enumerate all leaf paths and values in a dictionary or list."""
    items: list[tuple[str, Any]] = []

    if isinstance(data, dict):
        for k, v in data.items():
            curr_path = f"{prefix}.{k}"
            if isinstance(v, (dict, list)):
                items.extend(flatten_paths(v, curr_path))
            else:
                items.append((curr_path, v))
    elif isinstance(data, list):
        for idx, elem in enumerate(data):
            curr_path = f"{prefix}[{idx}]"
            if isinstance(elem, (dict, list)):
                items.extend(flatten_paths(elem, curr_path))
            else:
                items.append((curr_path, elem))
    else:
        items.append((prefix, data))

    return items
