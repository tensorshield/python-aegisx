from typing import Any
from typing import Self

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import MGF1
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.padding import PSS
import pydantic
from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler

from ._oidmapped import OIDMapped


class PaddingAlgorithm(OIDMapped):
    __module__: str = 'aegisx.types'
    __oid__mapping__ = {
        'EMSA-PKCS1-v1_5'   : ('name', 'EMSA-PKCS1-v1_5'),
        'EMSA-PSS'          : ('name', 'EMSA-PSS'),
        'RSAES-OAEP'        : ('name', 'RSAES-OAEP'),
        'RSAES-PKCS1-v1_5'  : ('name', 'RSAES-PKCS1-v1_5')
    }

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.with_info_plain_validator_function(cls.discover),
            python_schema=core_schema.with_info_plain_validator_function(cls.discover),
            serialization=core_schema.plain_serializer_function_ser_schema(str),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _: CoreSchema,
        handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(core_schema.str_schema())

    @classmethod
    def discover(
        cls,
        value: str | Self,
        info: pydantic.ValidationInfo
    ) -> Self:
        if isinstance(value, cls):
            return value
        assert isinstance(value, str)
        if value not in cls.__oid__mapping__:
            raise ValueError(f'Unknown padding algorithm: {value}')
        source, name = cls.__oid__mapping__[value]
        return cls(source, name, oid=value)

    def __init__(self, source: str, name: str, oid: str | None = None):
        self.source = source
        self.name = name
        self.oid = oid

    def padding(self, h: hashes.HashAlgorithm | None = None):
        match self.name:
            case 'EMSA-PKCS1-v1_5':
                return PKCS1v15()
            case 'EMSA-PSS':
                if h is None:
                    raise TypeError(f'{self.name} requires a hash algorithm.')
                return PSS(
                    mgf=MGF1(h),
                    salt_length=PSS.MAX_LENGTH
                )
            case 'RSAES-PKCS1-v1_5':
                return PKCS1v15()
            case 'RSAES-OAEP':
                if h is None:
                    raise TypeError(f'{self.name} requires a hash algorithm.')
                return OAEP(
                    mgf=MGF1(h),
                    algorithm=type(h)(),
                    label=None
                )
            case _:
                raise NotImplementedError(self.name)

    def __str__(self):
        return self.name

    def __repr__(self):
        return f'<PaddingAlgorithm: {self.name} (oid: {self.oid})>'