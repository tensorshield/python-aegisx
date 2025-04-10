import pydantic

from aegisx.ext.oauth.types import SpaceSeparatedSet


def test_dump():
    a = pydantic.TypeAdapter(SpaceSeparatedSet)
    v = SpaceSeparatedSet({"foo", "bar", "baz"})
    assert a.dump_python(v) == "bar baz foo"


def test_dump_json():
    a = pydantic.TypeAdapter(SpaceSeparatedSet)
    v = SpaceSeparatedSet({"foo", "bar", "baz"})
    assert a.dump_json(v) == b'"bar baz foo"'


def test_load_string():
    a = pydantic.TypeAdapter(SpaceSeparatedSet)
    v = "foo bar baz"
    assert a.validate_python(v) == SpaceSeparatedSet({"foo", "bar", "baz"})


def test_load_set():
    a = pydantic.TypeAdapter(SpaceSeparatedSet)
    v = {"foo", "bar", "baz"}
    assert a.validate_python(v) == SpaceSeparatedSet({"foo", "bar", "baz"})


def test_load_json():
    a = pydantic.TypeAdapter(SpaceSeparatedSet)
    v = '"bar baz foo"'
    assert a.validate_json(v) == SpaceSeparatedSet({"foo", "bar", "baz"})


def test_load_json_dict():
    a = pydantic.TypeAdapter(dict[str, SpaceSeparatedSet])
    v = '{"scope": "bar baz foo"}'
    assert a.validate_json(v) == {'scope': SpaceSeparatedSet({"foo", "bar", "baz"})}


def test_load_json_list():
    a = pydantic.TypeAdapter(list[SpaceSeparatedSet])
    v = '["bar baz foo"]'
    assert a.validate_json(v) == [SpaceSeparatedSet({"foo", "bar", "baz"})]