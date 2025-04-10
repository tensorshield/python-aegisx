from typing import Any

import pydantic
import pytest

from aegisx.ext.iam.types import Permission
from aegisx.ext.iam.types import WildcardPermission



VALID_INPUTS: list[tuple[str, type[WildcardPermission]]] = [
    ('foo', WildcardPermission),
    ('foo.*', WildcardPermission),
    ('foo.**', WildcardPermission),
    ('foo.bar.*', WildcardPermission),
    ('foo.bar.baz.qux', WildcardPermission),
    ('foo.*.baz.*.baz', WildcardPermission),
]


INVALID_INPUTS: list[str] = [
    'foo..',
    'Foo',
    'foo1.bar.baz',
    'foo1.bar*.baz',
    'foo.**.bar.**',
    'foo.**.bar',
    'foo.b*r.bar',
]


# Equality between Wildcard Permissions and Permissions where
# the wildcard is on the left side
MIXED_EQ_WILDCARD_PERMISSION_PERMISSION: list[Any] = [
    (WildcardPermission('foo.bar.baz'), Permission('foo.bar.baz')),
    (WildcardPermission('foo.*.baz'), Permission('foo.bar.baz')),
    (WildcardPermission('foo.**'), Permission('foo.bar.baz')),
    (WildcardPermission('foo.bar.*'), Permission('foo.bar.baz')),
    (WildcardPermission('*.bar.*'), Permission('foo.bar.baz')),
    (WildcardPermission('*'), Permission('foo')),
    (WildcardPermission('*'), Permission('bar')),
    (WildcardPermission('**'), Permission('foo.bar.baz')),
    (WildcardPermission('foo.*.baz.**'), Permission('foo.bar.baz.qux')),
]

MIXED_EQ_PERMISSION_WILDCARD_PERMISSION: list[Any] = [
    (x[1], x[0]) for x in MIXED_EQ_WILDCARD_PERMISSION_PERMISSION
]

MIXED_EQ = [
    *MIXED_EQ_PERMISSION_WILDCARD_PERMISSION,
    *MIXED_EQ_WILDCARD_PERMISSION_PERMISSION
]

MIXED_NEQ_WILDCARD_PERMISSION_PERMISSION: list[Any] = [
    (WildcardPermission('foo.bar.baz'), Permission('foo.bar.qux')),
    (WildcardPermission('foo.*.baz'), Permission('foo.bar.qux')),
    (WildcardPermission('foo.*.baz'), Permission('foo.bar.baz.fux')),
    (WildcardPermission('foo.*.baz'), Permission('foo.bar.qux.fux')),
    (WildcardPermission('foo.**'), Permission('qux.bar.baz')),
    (WildcardPermission('foo.bar.*'), Permission('foo.bar.qux')),
    (WildcardPermission('*.bar.*'), Permission('foo.qux.baz')),
    (WildcardPermission('*'), Permission('foo.bar')),
    (WildcardPermission('**'), Permission('foo.bar.baz')),
    (WildcardPermission('foo.*.baz.**'), Permission('foo.bar.taz.qux')),

    # ChatGPT-generated:
    # Wildcard does not match middle mismatch
    (WildcardPermission('foo.*.baz'), Permission('foo.baz.baz')),  # middle 'baz' instead of wildcard
    (WildcardPermission('foo.*.baz'), Permission('foo.bar.bar')),  # end doesn't match

    # Wildcard not deep enough
    (WildcardPermission('foo.*'), Permission('foo.bar.baz')),  # extra depth
    (WildcardPermission('foo.bar.*'), Permission('foo.bar.baz.qux')),  # 2 levels deep

    # Prefix and suffix match, middle doesn't
    (WildcardPermission('foo.**.baz'), Permission('foo.baz.baz')),  # middle 'baz' doesn't match recursive

    # Starts with wildcard but diverges
    (WildcardPermission('**.bar.baz'), Permission('foo.bar.qux')),  # end doesn't match
    (WildcardPermission('**.bar.baz'), Permission('bar.baz.qux')),  # too long

    # All wildcards but wrong structure
    (WildcardPermission('*'), Permission('foo.bar.baz')),  # wildcard too shallow
    (WildcardPermission('foo.*'), Permission('foo.bar.baz')),  # wildcard too shallow

    # Subdomain mismatch
    (WildcardPermission('foo.bar.*'), Permission('foo.baz.baz')),  # bar != baz
    (WildcardPermission('foo.bar.**'), Permission('foo.baz.baz')),  # bar != baz even for recursive

    # Deep mismatch
    (WildcardPermission('foo.**.baz'), Permission('foo.qux.quux')),  # missing end match

    # Mismatched sibling nodes
    (WildcardPermission('foo.bar.qux'), Permission('foo.bar.quux')),  # close but not equal
    (WildcardPermission('foo.bar.*.qux'), Permission('foo.bar.baz.quux')),  # end mismatch

    # Wildcard not greedy
    (WildcardPermission('foo.**.bar'), Permission('foo.bar.baz')),  # bar is early, not final

    # Too shallow
    (WildcardPermission('foo.bar.baz.qux'), Permission('foo.bar.baz')),  # shorter path

    # Wildcards in odd positions
    (WildcardPermission('*.*.*'), Permission('foo.bar.baz.qux')),  # too long
    (WildcardPermission('*.*.*.*'), Permission('foo.bar.baz')),  # too short

    # Similar wildcard pattern, wrong match
    (WildcardPermission('foo.**.baz.**'), Permission('foo.bar.baz')),  # needs more depth

    # Invalid nesting
    (WildcardPermission('foo.bar.*.qux'), Permission('foo.bar.baz.fux')),  # last part doesn't match
    (WildcardPermission('foo.bar.baz.*'), Permission('foo.bar.baz')),  # too short
]

MIXED_NEQ_PERMISSION_WILDCARD_PERMISSION: list[Any] = [
    (x[1], x[0]) for x in MIXED_NEQ_WILDCARD_PERMISSION_PERMISSION
]

MIXED_NEQ = [
    *MIXED_NEQ_WILDCARD_PERMISSION_PERMISSION,
    *MIXED_NEQ_PERMISSION_WILDCARD_PERMISSION
]


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_validate_python(value: str, cls: type[WildcardPermission]):
    adapter: pydantic.TypeAdapter[WildcardPermission] = pydantic.TypeAdapter(WildcardPermission)
    permission = adapter.validate_python(value)
    assert isinstance(permission, cls)


@pytest.mark.parametrize("value", INVALID_INPUTS)
def test_validate_python_invalid(value: str):
    adapter: pydantic.TypeAdapter[WildcardPermission] = pydantic.TypeAdapter(WildcardPermission)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(value)


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_validate_json(value: str, cls: type[WildcardPermission]):
    adapter: pydantic.TypeAdapter[WildcardPermission] = pydantic.TypeAdapter(WildcardPermission)
    permission = adapter.validate_json(f'"{value}"', strict=True)
    assert isinstance(permission, cls)


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_dump_python(value: str, cls: type[WildcardPermission]):
    adapter: pydantic.TypeAdapter[WildcardPermission] = pydantic.TypeAdapter(WildcardPermission)
    p1 = adapter.validate_python(value)
    assert adapter.validate_python(adapter.dump_python(p1)) == p1


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_dump_json(value: str, cls: type[WildcardPermission]):
    adapter: pydantic.TypeAdapter[WildcardPermission] = pydantic.TypeAdapter(WildcardPermission)
    p1 = adapter.validate_python(value)
    assert adapter.validate_json(adapter.dump_json(p1)) == p1


def test_json_schema():
    Model = type('Model', (pydantic.BaseModel,), {
        '__annotations__': {'permission': WildcardPermission}
    })
    schema = Model.model_json_schema()
    assert 'permission' in schema['properties']


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_eq_self(value: str, cls: type[WildcardPermission]):
    adapter: pydantic.TypeAdapter[WildcardPermission] = pydantic.TypeAdapter(WildcardPermission)
    p1 = adapter.validate_python(value)
    p2 = adapter.validate_python(value)
    assert p1 == p2


@pytest.mark.parametrize("a,b", MIXED_EQ)
def test_eq_mixed(
    a: Permission | WildcardPermission,
    b: Permission | WildcardPermission,
):
    assert a == b


@pytest.mark.parametrize("a,b", MIXED_NEQ)
def test_neq_mixed(
    a: Permission | WildcardPermission,
    b: Permission | WildcardPermission,
):
    assert a != b


def test_expand():
    w = WildcardPermission('foo.*')
    permissions = {
        Permission('foo.bar'),
        Permission('foo.bar.baz'),
        Permission('qux.bar.baz'),
    }
    assert w.expand(permissions) == {
        Permission('foo.bar'),
        Permission('foo.bar.baz')
    }