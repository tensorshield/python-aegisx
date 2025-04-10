from typing import Any

import pydantic
from pyasn1.codec.der.decoder import decode
from pyasn1_modules.rfc2315 import AttributeTypeAndValue
from pyasn1_modules.rfc2315 import Name
from pyasn1_modules.rfc2315 import RelativeDistinguishedName


OID_MAP: dict[str, str] = {
    '2.5.4.3'   : 'common_name',
    '2.5.4.6'   : 'country',
    '2.5.4.10'  : 'organization_name',
    '2.5.4.11'  : 'organization_unit',
    '2.5.4.7'   : 'locality',
    '2.5.4.8'   : 'region',
    '2.5.4.97'  : 'organization_id',
}


class Issuer(pydantic.BaseModel):
    common_name: str = pydantic.Field(
        default=...
    )

    country: str | None = pydantic.Field(
        default=None
    )

    organization_name: str | None = pydantic.Field(
        default=None
    )

    organization_unit: str | None = pydantic.Field(
        default=None
    )

    locality: str | None = pydantic.Field(
        default=None
    )

    region: str | None = pydantic.Field(
        default=None
    )

    organization_id: str | None = pydantic.Field(
        default=None
    )

    @pydantic.model_validator(mode='before')
    @classmethod
    def preprocess(cls, value: Any | dict[str, str] | Name):
        if isinstance(value, Name):
            names: list[RelativeDistinguishedName] = list(value[0]) # type: ignore
            value = {}
            for rdn in names:
                for name in rdn: # type: ignore
                    assert isinstance(name, AttributeTypeAndValue)
                    oid = str(name['type']) # type: ignore
                    try:
                        x, _ = decode(name['value']) # type: ignore
                        if _:
                            raise ValueError("invalid DER-encoding")
                        value[ OID_MAP[oid] ] = str(x) # type: ignore
                    except KeyError:
                        raise ValueError(f"unknown OID: {oid}")
        return value