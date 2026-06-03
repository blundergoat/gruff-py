"""Negative calibration fixture: shapes the rule must leave clean even with a local class."""

import unittest


class ShapeService:
    label = "shape"
    slug: str  # bare annotation - no runtime attribute

    def __init__(self) -> None:
        self.count = 0  # instance-only attribute

    def render(self) -> str:
        return "shape"


def test_behavioural_value():
    service = ShapeService()
    assert service.render() == "shape"


def test_dynamic_member_name():
    member = "render"
    assert hasattr(ShapeService, member)


def test_instance_object(service):
    assert hasattr(service, "render")


def test_imported_symbol():
    from datetime import datetime

    assert hasattr(datetime, "fromisoformat")


def test_bare_annotation_only():
    assert hasattr(ShapeService, "slug")


def test_instance_only_attribute():
    assert hasattr(ShapeService, "count")


def test_undeclared_member():
    assert hasattr(ShapeService, "missing")


def test_private_member_owned_by_private_reflection():
    assert hasattr(ShapeService, "_secret")


def test_callable_attribute_is_not_a_method():
    assert callable(ShapeService.label)


def test_negated_existence():
    assert not hasattr(ShapeService, "render")


class TestShapeService(unittest.TestCase):
    def test_runtime_value(self):
        self.assertEqual(ShapeService().render(), "shape")

    def test_assert_false_existence(self):
        self.assertFalse(hasattr(ShapeService, "render"))
