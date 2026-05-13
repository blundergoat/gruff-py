"""Cyclomatic complexity ground-truth fixture.

Expected radon values are recorded in `radon_ground_truth.md`. The unit test
`tests/unit/rule/complexity/test_cyclomatic_complexity_rule.py::test_matches_radon_ground_truth`
asserts gruff-py's values match these by name.
"""


def simple(x):
    return x + 1


def with_branches(x):
    if x > 0:
        return 1
    elif x < 0:
        return -1
    else:
        return 0


def with_loop(items):
    total = 0
    for item in items:
        if item > 0:
            total += item
    return total


def with_boolops(a, b, c):
    if a and b or c:
        return 1
    return 0


def with_match(x):
    match x:
        case 1:
            return "one"
        case 2:
            return "two"
        case _:
            return "other"


def with_comprehension(items):
    return [x * 2 for x in items if x > 0]


def t1():
    try:
        x = 1
    except ValueError:
        x = 2
    return x


def t2():
    try:
        x = 1
    except ValueError:
        x = 2
    except KeyError:
        x = 3
    return x


def a1(x):
    assert x > 0
    return x


def a2(x):
    assert x > 0
    assert x < 100
    return x
