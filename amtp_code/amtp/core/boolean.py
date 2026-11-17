"""Boolean expressions with AND / OR and parentheses.

Used twice: for search queries (leaves are keywords) and for access
policies (leaves are attributes). AND binds tighter than OR, like
multiplication before addition.

AST form:  ("leaf", value) | ("AND", [children]) | ("OR", [children])

Multi-word keywords (e.g. RAKE phrases of the arXiv dataset) are written in double quotes:
    "machine learning" AND "neural network"
"""
import re

from .hashing import _enc_node

_TOKEN = re.compile(r"\s*(\(|\)|&&|\|\||\"[^\"]+\"|[A-Za-z0-9_\-]+)")


class ParseError(ValueError):
    pass


def parse(text: str):
    tokens = _tokenize(text)
    if not tokens:
        raise ParseError("Empty expression")
    ast, pos = _parse_or(tokens, 0)
    if pos != len(tokens):
        raise ParseError(f"Unexpected '{tokens[pos]}'")
    return canonical(ast)


def _tokenize(text):
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ParseError(f"Cannot read '{text[pos:]}'")
        tok = m.group(1)
        upper = tok.upper()
        if tok.startswith('"'):
            tok = ("phrase", " ".join(tok[1:-1].split()))   # quoted phrase is always a keyword
        elif upper in ("AND", "&&"):
            tok = "AND"
        elif upper in ("OR", "||"):
            tok = "OR"
        tokens.append(tok)
        pos = m.end()
    return tokens


def _parse_or(tokens, pos):
    left, pos = _parse_and(tokens, pos)
    children = [left]
    while pos < len(tokens) and tokens[pos] == "OR":
        right, pos = _parse_and(tokens, pos + 1)
        children.append(right)
    return (children[0] if len(children) == 1 else ("OR", children)), pos


def _parse_and(tokens, pos):
    left, pos = _parse_atom(tokens, pos)
    children = [left]
    while pos < len(tokens) and tokens[pos] == "AND":
        right, pos = _parse_atom(tokens, pos + 1)
        children.append(right)
    return (children[0] if len(children) == 1 else ("AND", children)), pos


def _parse_atom(tokens, pos):
    if pos >= len(tokens):
        raise ParseError("Expression ends too early")
    tok = tokens[pos]
    if isinstance(tok, tuple):
        return ("leaf", tok[1].lower()), pos + 1
    if tok == "(":
        node, pos = _parse_or(tokens, pos + 1)
        if pos >= len(tokens) or tokens[pos] != ")":
            raise ParseError("Missing ')'")
        return node, pos + 1
    if tok in ("AND", "OR", ")"):
        raise ParseError(f"Unexpected '{tok}'")
    return ("leaf", tok.lower()), pos + 1


def canonical(ast):
    """Canonical B_Q: flatten nested same operators, drop duplicate children, apply absorption
    (X AND (X OR Y) = X, X OR (X AND Y) = X), collapse one-child nodes and sort children by
    their binary encoding. Expressions that differ only by order, grouping, repetition or
    absorption get the same tree, hence the same Enc(B_Q) and the same query digest."""
    if ast[0] == "leaf":
        return ("leaf", ast[1])
    op = ast[0]
    flat = []
    for child in (canonical(c) for c in ast[1]):
        flat.extend(child[1] if child[0] == op else [child])
    unique = {_key(c): c for c in flat}
    absorbed = {k for k, c in unique.items()
                if c[0] != "leaf" and any(_key(g) in unique and _key(g) != k for g in c[1])}
    children = [unique[k] for k in sorted(unique) if k not in absorbed]
    return children[0] if len(children) == 1 else (op, children)


def _key(ast) -> bytes:
    return _enc_node(ast)


def leaves(ast) -> set:
    if ast[0] == "leaf":
        return {ast[1]}
    return set().union(*(leaves(c) for c in ast[1]))


def map_leaves(ast, fn):
    if ast[0] == "leaf":
        return ("leaf", fn(ast[1]))
    return (ast[0], [map_leaves(c, fn) for c in ast[1]])


def evaluate(ast, leaf_sets: dict) -> set:
    """Eval: leaf -> its set, AND -> intersection, OR -> union.
    AND starts from the smallest set (smallest-first optimisation)."""
    if ast[0] == "leaf":
        return set(leaf_sets.get(ast[1], set()))
    parts = [evaluate(c, leaf_sets) for c in ast[1]]
    if ast[0] == "AND":
        parts.sort(key=len)
        result = parts[0]
        for p in parts[1:]:
            result = result & p
        return result
    return set().union(*parts)


def focus(ast, known: dict):
    """The partitions every match of B_Q must lie in, from the leaves whose full partition set is known
    (`known`: leaf -> set of partitions). None = not bounded (some needed leaf is unknown).
    leaf: its set if known · AND: intersection of the bounded children · OR: union, bounded only if every
    child is. A file matching B_Q lies in a partition of every keyword it satisfies, so by induction it
    lies in focus(B_Q). Server (AND pruning) and user apply this same rule."""
    if ast[0] == "leaf":
        return set(known[ast[1]]) if ast[1] in known else None
    parts = [focus(c, known) for c in ast[1]]
    if ast[0] == "AND":
        bounded = sorted((p for p in parts if p is not None), key=len)
        if not bounded:
            return None
        out = set(bounded[0])
        for p in bounded[1:]:
            out &= p
        return out
    if any(p is None for p in parts):
        return None
    return set().union(*parts)


def to_text(ast) -> str:
    if ast[0] == "leaf":
        return f'"{ast[1]}"' if " " in ast[1] else ast[1]
    inner = f" {ast[0]} ".join(
        to_text(c) if c[0] == "leaf" else f"({to_text(c)})" for c in ast[1]
    )
    return inner


def from_json(obj):
    """Rebuild an AST that went through JSON (tuples become lists)."""
    if obj[0] == "leaf":
        return ("leaf", obj[1])
    return (obj[0], [from_json(c) for c in obj[1]])
