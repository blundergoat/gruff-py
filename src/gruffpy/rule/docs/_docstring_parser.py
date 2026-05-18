"""Docstring parsing wrapper for the documentation pillar.

Defined by ADR-005. Rules in this pillar consume :func:`parse_docstring` and
:class:`ParsedDocstring` from here; the third-party ``docstring_parser`` library
is imported only by this module so the dependency has exactly one swap point.
"""

import ast
from dataclasses import dataclass
from enum import StrEnum

import docstring_parser as _dp


class DocstringStyle(StrEnum):
    GOOGLE = "google"
    NUMPY = "numpy"
    SPHINX = "sphinx"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DocstringField:
    """One field entry inside a parsed docstring.

    For ``@param`` style entries, *name* is the parameter name and *type_hint*
    is the documented type if any. For ``@return`` / ``Returns:`` entries,
    *name* is ``None`` and *type_hint* / *description* carry the documented
    return shape. For ``@raises`` / ``Raises:`` entries, *name* is the
    exception class name and *type_hint* is ``None``.
    """

    name: str | None
    type_hint: str | None
    description: str | None


@dataclass(frozen=True, slots=True)
class ParsedDocstring:
    """Normalised view over a docstring across all supported styles."""

    summary: str | None
    description: str | None
    params: tuple[DocstringField, ...]
    returns: DocstringField | None
    raises: tuple[DocstringField, ...]
    style: DocstringStyle


_STYLE_MAP: dict[_dp.DocstringStyle, DocstringStyle] = {
    _dp.DocstringStyle.GOOGLE: DocstringStyle.GOOGLE,
    _dp.DocstringStyle.NUMPYDOC: DocstringStyle.NUMPY,
    _dp.DocstringStyle.REST: DocstringStyle.SPHINX,
    _dp.DocstringStyle.EPYDOC: DocstringStyle.SPHINX,
}


def parse_docstring(text: str) -> ParsedDocstring | None:
    """Parse docstring text with style auto-detection.

    Returns a :class:`ParsedDocstring` with summary, description, and
    normalised param/return/raises tuples. ``None`` is returned only when
    *text* is empty, whitespace-only, or the parser raises — in which case
    field-mismatch rules should skip the docstring rather than emit findings.

    Args:
        text: Raw docstring text to parse.

    Returns:
        Parsed docstring fields, or None when parsing should be skipped.
    """
    if not text or not text.strip():
        return None
    try:
        raw = _dp.parse(text)
    except _dp.ParseError:
        return None

    style = (
        _STYLE_MAP.get(raw.style, DocstringStyle.UNKNOWN) if raw.style else DocstringStyle.UNKNOWN
    )

    params = tuple(
        DocstringField(name=p.arg_name, type_hint=p.type_name, description=p.description)
        for p in raw.params
    )
    returns: DocstringField | None = None
    if raw.returns is not None:
        returns = DocstringField(
            name=None,
            type_hint=raw.returns.type_name,
            description=raw.returns.description,
        )
    raises = tuple(
        DocstringField(name=r.type_name, type_hint=None, description=r.description)
        for r in raw.raises
    )

    return ParsedDocstring(
        summary=raw.short_description,
        description=raw.long_description,
        params=params,
        returns=returns,
        raises=raises,
        style=style,
    )


_DocstringHostNode = ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


def extract_docstring(node: _DocstringHostNode) -> str | None:
    """Return the raw docstring text for a supported AST node.

    Thin wrapper over :func:`ast.get_docstring` so docs rules import a single
    helper module rather than mixing stdlib calls with parser calls.

    Args:
        node: Module, class, function, or async function node to inspect.

    Returns:
        Raw docstring text, or None when the node has no docstring.
    """
    return ast.get_docstring(node, clean=False)
