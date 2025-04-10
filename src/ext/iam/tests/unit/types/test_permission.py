import pydantic
import pytest

from aegisx.ext.iam.types import Permission



VALID_INPUTS: list[tuple[str, type[Permission]]] = [
    ('foo', Permission),
    ('foo.bar', Permission),
    ('foo.bar.baz', Permission),
    ('foo.bar.baz.qux', Permission),
]


INVALID_INPUTS: list[str] = [
    'foo..',
    'Foo',
    'foo1.bar.baz'
]


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_validate_python(value: str, cls: type[Permission]):
    adapter: pydantic.TypeAdapter[Permission] = pydantic.TypeAdapter(Permission)
    permission = adapter.validate_python(value)
    assert isinstance(permission, cls)


@pytest.mark.parametrize("value", INVALID_INPUTS)
def test_validate_python_invalid(value: str):
    adapter: pydantic.TypeAdapter[Permission] = pydantic.TypeAdapter(Permission)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(value)


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_validate_json(value: str, cls: type[Permission]):
    adapter: pydantic.TypeAdapter[Permission] = pydantic.TypeAdapter(Permission)
    permission = adapter.validate_json(f'"{value}"', strict=True)
    assert isinstance(permission, cls)


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_dump_python(value: str, cls: type[Permission]):
    adapter: pydantic.TypeAdapter[Permission] = pydantic.TypeAdapter(Permission)
    p1 = adapter.validate_python(value)
    assert adapter.validate_python(adapter.dump_python(p1)) == p1


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_dump_json(value: str, cls: type[Permission]):
    adapter: pydantic.TypeAdapter[Permission] = pydantic.TypeAdapter(Permission)
    p1 = adapter.validate_python(value)
    assert adapter.validate_json(adapter.dump_json(p1)) == p1


def test_json_schema():
    Model = type('Model', (pydantic.BaseModel,), {
        '__annotations__': {'permission': Permission}
    })
    schema = Model.model_json_schema()
    assert 'permission' in schema['properties']


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_eq_self(value: str, cls: type[Permission]):
    adapter: pydantic.TypeAdapter[Permission] = pydantic.TypeAdapter(Permission)
    p1 = adapter.validate_python(value)
    p2 = adapter.validate_python(value)
    assert p1 == p2


def test_expand():
    w = Permission('foo.bar.baz')
    permissions = {
        Permission('foo.bar'),
        Permission('foo.bar.baz'),
        Permission('foo.qux.baz'),
    }
    assert w.expand(permissions) == {Permission('foo.bar.baz')}