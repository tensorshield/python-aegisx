from typing import Any

import pydantic
import pytest

from aegisx.ext.iam.types import AnonymousPrincipal
from aegisx.ext.iam.types import AuthenticatedPrincipal
from aegisx.ext.iam.types import DomainPrincipal
from aegisx.ext.iam.types import GroupPrincipal
from aegisx.ext.iam.types import ServiceAccountPrincipal
from aegisx.ext.iam.types import UserPrincipal
from aegisx.ext.iam.types import Principal
from aegisx.ext.iam.types import PrincipalType



VALID_INPUTS: list[tuple[str, type[Principal[Any]]]] = [
    ('user:alex@example.com', UserPrincipal),
    ('serviceAccount:my-service-account@my-project.iam.gserviceaccount.com', ServiceAccountPrincipal),
    ('allUsers', AnonymousPrincipal),
    ('allAuthenticatedUsers', AuthenticatedPrincipal),
    ('domain:test.tensorshield.ai', DomainPrincipal),
    ('group:group@test.tensorshield.ai', GroupPrincipal),
]

LT_INPUTS_SELF: list[tuple[PrincipalType, PrincipalType]] = [
    (UserPrincipal.validate('user:alex@example.com'), UserPrincipal.validate('user:blex@example.com')),
    (ServiceAccountPrincipal.validate('serviceAccount:alex@example.com'), ServiceAccountPrincipal.validate('serviceAccount:blex@example.com')),
    (DomainPrincipal.validate('domain:a.com'), DomainPrincipal.validate('domain:b.com'))
]

GT_INPUTS_SELF: list[tuple[PrincipalType, PrincipalType]] = [
    (x[1], x[0]) for x in LT_INPUTS_SELF
]


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_validate_python(value: str, cls: type[Principal]):
    adapter: pydantic.TypeAdapter[PrincipalType] = pydantic.TypeAdapter(PrincipalType)
    principal = adapter.validate_python(value)
    assert isinstance(principal, cls)


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_validate_json(value: str, cls: type[Principal]):
    adapter: pydantic.TypeAdapter[PrincipalType] = pydantic.TypeAdapter(PrincipalType)
    principal = adapter.validate_json(f'"{value}"', strict=True)
    assert isinstance(principal, cls)


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_dump_python(value: str, cls: type[Principal]):
    adapter: pydantic.TypeAdapter[PrincipalType] = pydantic.TypeAdapter(PrincipalType)
    p1 = adapter.validate_python(value)
    assert adapter.validate_python(adapter.dump_python(p1)) == p1


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_dump_json(value: str, cls: type[Principal]):
    adapter: pydantic.TypeAdapter[PrincipalType] = pydantic.TypeAdapter(PrincipalType)
    p1 = adapter.validate_python(value)
    assert adapter.validate_json(adapter.dump_json(p1)) == p1


def test_json_schema():
    Model = type('Model', (pydantic.BaseModel,), {
        '__annotations__': {'principal': PrincipalType}
    })
    schema = Model.model_json_schema()
    assert 'principal' in schema['properties']


@pytest.mark.parametrize("value,cls", VALID_INPUTS)
def test_eq_self(value: str, cls: type[Principal]):
    adapter: pydantic.TypeAdapter[PrincipalType] = pydantic.TypeAdapter(PrincipalType)
    p1 = adapter.validate_python(value)
    p2 = adapter.validate_python(value)
    assert p1 == p2


@pytest.mark.parametrize("a,b", LT_INPUTS_SELF)
def test_lt_self(a: PrincipalType, b: PrincipalType):
    assert a < b


@pytest.mark.parametrize("a,b", GT_INPUTS_SELF)
def test_gt_self(a: PrincipalType, b: PrincipalType):
    assert a > b