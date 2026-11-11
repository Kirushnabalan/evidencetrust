from __future__ import annotations

import re

JAVA_KEYWORDS = {
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
    "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
    "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
    "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp",
    "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void",
    "volatile", "while", "true", "false", "null", "var", "record", "yield", "String", "Object",
}
_IDENT = re.compile(r"\b[A-Za-z_$][\w$]*\b")
_COMMENT_OR_STR = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


def _mask_comments_strings(code: str) -> str:
    return _COMMENT_OR_STR.sub(lambda m: " " * len(m.group(0)), code)


def identifier_pairs(code: str) -> list[tuple[int, int]]:
    """(char pos of first occurrence, char pos of later occurrence) for every reused identifier."""
    first: dict[str, int] = {}
    pairs = []
    for m in _IDENT.finditer(_mask_comments_strings(code)):
        name = m.group(0)
        if name in JAVA_KEYWORDS:
            continue
        if name in first:
            pairs.append((first[name], m.start()))
        else:
            first[name] = m.start()
    return pairs


def d1_token_visibility(n_tokens: int, max_tokens: int = 510) -> float:
    if n_tokens <= 0:
        return 1.0
    return min(1.0, max_tokens / n_tokens)


def d2_context_covisibility(code: str, visible_char_end: int) -> float:
    pairs = identifier_pairs(code)
    if not pairs:
        return 1.0
    seen = sum(1 for a, b in pairs if a < visible_char_end and b < visible_char_end)
    return seen / len(pairs)


def visible_lines(code: str, visible_char_end: int) -> tuple[int, int]:
    """(fully/partly visible lines, total lines)."""
    total = code.count("\n") + 1
    vis = code[:visible_char_end].count("\n") + 1 if visible_char_end > 0 else 0
    return min(vis, total), total