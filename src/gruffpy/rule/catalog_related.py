"""Related-rule metadata for built-in catalogue entries."""

RELATED_RULES: dict[str, tuple[str, ...]] = {
    # Naming hygiene cluster.
    "naming.abbreviation": ("naming.identifier-quality", "naming.short-variable"),
    "naming.identifier-quality": ("naming.abbreviation", "naming.short-variable"),
    "naming.short-variable": ("naming.abbreviation", "naming.identifier-quality"),
    "naming.generic-function": ("naming.identifier-quality",),
    "naming.test-naming-consistency": ("test-quality.naming-consistency",),
    # docs.missing-* family.
    "docs.missing-class-docstring": (
        "docs.missing-function-docstring",
        "docs.missing-module-docstring",
        "docs.dataclass-attributes",
    ),
    "docs.missing-function-docstring": (
        "docs.missing-class-docstring",
        "docs.missing-module-docstring",
        "docs.missing-param-doc",
        "docs.missing-return-doc",
    ),
    "docs.missing-module-docstring": (
        "docs.missing-class-docstring",
        "docs.missing-function-docstring",
        "docs.missing-readme",
    ),
    "docs.missing-param-doc": (
        "docs.missing-function-docstring",
        "docs.missing-return-doc",
        "docs.missing-raises-doc",
        "docs.stale-param-doc",
    ),
    "docs.missing-return-doc": (
        "docs.missing-function-docstring",
        "docs.missing-param-doc",
        "docs.missing-raises-doc",
    ),
    "docs.missing-raises-doc": (
        "docs.missing-function-docstring",
        "docs.missing-param-doc",
        "docs.missing-return-doc",
    ),
    "docs.missing-readme": ("docs.missing-module-docstring",),
    "docs.stale-param-doc": ("docs.missing-param-doc",),
    # Complexity / size siblings (function-level).
    "complexity.cyclomatic": (
        "complexity.cognitive",
        "size.function-length",
    ),
    "complexity.cognitive": (
        "complexity.cyclomatic",
        "size.function-length",
    ),
    "complexity.nesting-depth": ("complexity.cyclomatic", "complexity.cognitive"),
    "size.function-length": (
        "complexity.cyclomatic",
        "complexity.cognitive",
        "size.average-function-length",
    ),
    "size.average-function-length": ("size.function-length",),
    "size.parameter-count": ("size.function-length", "complexity.cyclomatic"),
    # Class-level size siblings.
    "size.class-length": ("size.public-method-count", "size.attribute-count"),
    "size.public-method-count": ("size.class-length", "size.attribute-count"),
    "size.attribute-count": ("size.class-length", "size.public-method-count"),
    "size.file-length": ("size.class-length", "size.function-length"),
    # Waste / dead-code overlap.
    "waste.empty-function": (),
    "waste.unreachable-code": ("dead-code.unused-private-attribute",),
    "dead-code.unused-private-attribute": (),
}
