"""Positive calibration fixture: assertions that only restate same-file declarations."""

import inspect
import unittest


class ShapeService:
    label = "shape"
    code: str = "default"

    def render(self) -> str:
        return "shape"


def test_class_declared():
    assert inspect.isclass(ShapeService)


def test_method_declared():
    assert hasattr(ShapeService, "render")
    assert callable(ShapeService.render)


def test_class_attribute_declared():
    assert hasattr(ShapeService, "label")
    assert hasattr(ShapeService, "code")


class TestShapeService(unittest.TestCase):
    def test_class_declared(self):
        self.assertTrue(inspect.isclass(ShapeService))

    def test_method_declared(self):
        self.assertTrue(hasattr(ShapeService, "render"))

    def test_attribute_declared(self):
        self.assertTrue(hasattr(ShapeService, "label"))
