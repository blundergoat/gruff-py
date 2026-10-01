"""Keep recognizable public constants out of the scanner's entropy warnings.

The detector checks complete values here before scoring their entropy.
Every segment must qualify, so a readable prefix cannot hide an opaque suffix.
"""

import re

# Compare complete public alphabets so appending opaque text cannot inherit their exception.
_ALPHABETS = frozenset(
    (
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_",
        "abcdefghijklmnopqrstuvwxyz0123456789-_",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    )
)
_PUBLIC_FORMAT = re.compile(r"(?:[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com|soljson-v[0-9]+\.[0-9]+\.[0-9]+\+commit\.[0-9a-f]{8}\.js)")
_GITHUB_COMMIT_URL = re.compile(
    r"https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9][A-Za-z0-9._-]{0,99}/commit/[0-9a-f]{40}"
)
# Only the complete portal route and its fixed navigation flags establish public application metadata.
_ENTRA_APPLICATION_URL = re.compile(
    r"https://entra\.microsoft\.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/isMSAApp~/false\?Microsoft_AAD_IAM_legacyAADRedirect=true"
)
# These nine complete container service IDs identify signature implementations, without accepting arbitrary short codes.
_SIGNATURE_SERVICE_ID = re.compile(r"security\.access_token_handler\.oidc\.signature\.(?:ES|RS|PS)(?:256|384|512)")
_NAME_SHAPE = re.compile(r"[A-Za-z0-9]+(?:[/._-]+[A-Za-z0-9]+)+")
_WORD_CASE = re.compile(r"(?:[A-Z]*[a-z]+|[A-Z]+|(?:[a-z]{3,}|[A-Z]{3,}|[A-Z][a-z]{2,})(?:[A-Z][a-z]{2,}|[A-Z]{3,})+)")


def is_public_entropy_shape(value: str) -> bool:
    """Check a complete literal before the scanner raises an entropy warning.

    Args:
        value: Complete candidate extracted by the detector; empty content matches no exception.

    Returns:
        Whether the value may skip entropy scoring; this heuristic does not prove it is public.
    """
    return (
        _ENTRA_APPLICATION_URL.fullmatch(value) is not None
        or _SIGNATURE_SERVICE_ID.fullmatch(value) is not None
        or _GITHUB_COMMIT_URL.fullmatch(value) is not None
        or value in _ALPHABETS
        or _PUBLIC_FORMAT.fullmatch(value) is not None
        or _is_bounded_public_format(value)
        or _is_structured_name(value)
    )


def is_public_entropy_url(url: str) -> bool:
    """Keep a complete public endpoint out of entropy warnings without trusting only its hostname.

    Args:
        url: Complete URL; credentials and unrecognized query or fragment content cannot receive an exception.

    Returns:
        Whether every URL component fits the bounded revision, portal, help-article or SQS format.
    """
    # A complete revision or portal reference identifies public metadata without carrying authentication material.
    if _GITHUB_COMMIT_URL.fullmatch(url) is not None or _ENTRA_APPLICATION_URL.fullmatch(url) is not None:
        return True
    article = re.fullmatch(r"https://support\.halaxy\.com/hc/[a-z]{2}-[a-z]{2}/articles/[0-9]{12,13}-([A-Za-z]+(?:-[A-Za-z]+)*)", url)
    # A developer may link to a help article; all label words still need the established case and length bounds.
    if article:
        return _is_public_article_label(article.group(1))
    queue = re.fullmatch(r"https://sqs\.[a-z]{2}(?:-[a-z]{3,16}){1,2}-[1-9]\.amazonaws\.com/[0-9]{12}/([A-Za-z0-9_-]+)(?:\?auto_setup=false)?", url)
    return queue is not None and _is_structured_name(queue.group(1))


def _is_public_article_label(label: str) -> bool:
    """Check every title word before a complete article URL or route may skip scoring.

    Args:
        label: Captured article title; empty or malformed words prevent an exception.

    Returns:
        Whether every word fits, allowing only the approved short joiners a, to and in.
    """
    return all(word in {"a", "to", "in"} or (3 <= len(word) <= 32 and _WORD_CASE.fullmatch(word)) for word in label.split("-"))


def _is_bounded_public_format(candidate: str) -> bool:
    """Keep established help routes and clinical codes quiet only when every word fits their complete format.

    Args:
        candidate: Whole source value; partial matches cannot grant an exception.

    Returns:
        Whether the complete format passes; False leaves the value eligible for a warning.
    """
    article = re.fullmatch(r"/hc/[a-z]{2}-[a-z]{2}/articles/[0-9]{12,13}-([A-Za-z]+(?:-[A-Za-z]+)*)", candidate)
    # A stored relative help link uses the article-only title grammar after its complete route matches.
    if article:
        return _is_public_article_label(article.group(1))
    formats = (
        r"/hc/[a-z]{2}-[a-z]{2}/(?:sections|categories)/[0-9]{12}-([A-Za-z]+(?:-[A-Za-z]+)*)",
        r"(?:PH|PHVS)_([A-Za-z]+)_HL7_V[0-9]{1,4}",
    )
    # A user may commit either public format; each must account for the entire literal.
    for pattern in formats:
        match = re.fullmatch(pattern, candidate)
        # A missing match or an opaque label leaves the value eligible for entropy scoring.
        if match and all(3 <= len(word) <= 32 and _WORD_CASE.fullmatch(word) for word in match.group(1).split("-")):
            return True
    return False


def _is_structured_name(value: str) -> bool:
    """Recognize readable names and repository paths without letting their words hide an opaque tail.

    Args:
        value: Whole source value; empty or malformed names remain eligible for scoring.

    Returns:
        Whether every segment passes and at least two word segments supply a strict letter majority.
    """
    # A committed path may start with two parent components or one rooted, hidden or current-directory prefix.
    value = re.sub(r"^(?:(?:\.\./){1,2}|\./|[/.])", "", value)
    # Missing segments or other punctuation keep the value eligible for a warning.
    if _NAME_SHAPE.fullmatch(value) is None:
        return False
    alphanumeric_count = word_letters = word_segment_count = 0
    # Readable directories do not excuse a random-looking filename; check each part independently.
    for segment in re.split(r"[/._-]+", value):
        count = _count_segment_word_letters(segment)
        # A rejected segment prevents the whole value from receiving the public-name exception.
        if count is None:
            return False
        alphanumeric_count += len(segment)
        word_letters += count
        word_segment_count += int(count > 0)
    return word_segment_count >= 2 and word_letters * 2 > alphanumeric_count


def _count_segment_word_letters(segment: str) -> int | None:
    """Count readable word letters without accepting an opaque suffix in the same segment.

    Args:
        segment: Populated ASCII alphanumeric part supplied by the whole-name check.

    Returns:
        Word-letter count; zero supplies no word evidence, and None rejects the whole name.
    """
    # Long undivided segments can hold opaque values, so they remain eligible for a warning.
    if len(segment) > 32:
        return None
    # Model codes and timestamps may occur in public paths but contribute no readable-word evidence.
    if re.fullmatch(
        r"(?:[vVxXrR][0-9]{1,4}|[0-9]{1,4}[bBeE]|[aA][0-9]{1,4}[bB]|FP[0-9]{1,4}|i18n|ec2|[mMtT][0-9]{2,3}|[0-9]{8}T[0-9]{4}(?:[0-9]{2})?Z)", segment
    ):
        return 0
    runs = re.findall(r"[A-Za-z]+|[0-9]+", segment)
    word_letters = digit_runs = 0
    # Inspect all letter and number runs so a readable opening cannot hide later random-looking text.
    for run in runs:
        # Numeric parts have tighter bounds when mixed with words, preserving warnings on opaque identifiers.
        if run.isdigit():
            digit_runs += 1
            # Repeated or long number runs prevent the name from receiving an exception.
            if len(run) > (6 if len(runs) == 1 else 4) or digit_runs > 2:
                return None
        else:
            # Arbitrary case changes or short interleaved letters do not establish a readable public name.
            if _WORD_CASE.fullmatch(run) is None or (len(runs) > 1 and len(run) < 3):
                return None
            # Short all-letter parts may occur in names but cannot supply the majority needed to skip a warning.
            if len(run) >= 3:
                word_letters += len(run)
    return word_letters
