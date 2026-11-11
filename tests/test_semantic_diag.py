from evidencetrust.diagnostics.semantic import (d1_token_visibility, d2_context_covisibility,
                                                identifier_pairs, visible_lines)
from evidencetrust.semantic.tokenize import encode_one

CODE = "int f(int a) {\n  int b = a + 1;\n  return b * a;\n}"


def test_d1():
    assert d1_token_visibility(100) == 1.0
    assert d1_token_visibility(1020) == 0.5
    assert d1_token_visibility(0) == 1.0


def test_pairs_ignore_keywords_comments_strings():
    p = identifier_pairs('int f(int a){ // a a a\n String s = "a"; return a; }')
    assert len(p) == 1          # only a(param) -> a(return)


def test_d2_full_and_partial():
    assert d2_context_covisibility(CODE, len(CODE)) == 1.0
    cut = CODE.index("return")  # last statement not visible
    assert abs(d2_context_covisibility(CODE, cut) - 1 / 3) < 1e-9


def test_visible_lines():
    assert visible_lines(CODE, len(CODE)) == (4, 4)
    assert visible_lines(CODE, CODE.index("return")) == (3, 4)


def test_encode_one_truncation():
    code = "a b c d e"
    offs = [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9)]
    r = encode_one(code, offs, [1, 2, 3, 4, 5], max_tokens=3)
    assert r["truncated"] and r["n_visible_tokens"] == 3 and r["visible_char_end"] == 5
    assert r["d1"] == 0.6 and r["input_ids"] == [1, 2, 3]
    r2 = encode_one(code, offs, [1, 2, 3, 4, 5], max_tokens=10)
    assert not r2["truncated"] and r2["d1"] == 1.0 and r2["d2"] == 1.0