import pydantic
import pytest

from aegisx.ext.jose.models import JWSCompactSerialization
from aegisx.ext.jose.models import JWSFlattenedSerialization
from aegisx.ext.jose.models import JWSGeneralSerialization


JOSEType = JWSCompactSerialization | JWSFlattenedSerialization | JWSGeneralSerialization

INPUT_FORMATS = ['compact', 'flattened', 'general']


@pytest.fixture
def adapter() -> pydantic.TypeAdapter[JOSEType]:
    return pydantic.TypeAdapter(JOSEType)
