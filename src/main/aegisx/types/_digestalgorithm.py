import _hashlib
import hashlib
from typing import overload
from typing import Any
from typing import Literal
from typing import Self

from cryptography.hazmat.primitives import hashes
import pydantic
from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler

from ._oidmapped import OIDMapped


class DigestAlgorithm(OIDMapped):
    __module__: str = 'aegisx.types'
    __oid__mapping__ = {
        '2.16.840.1.101.3.4.2.1': ('nist', 'sha256'),
        '2.16.840.1.101.3.4.2.2': ('nist', 'sha384'),
        '2.16.840.1.101.3.4.2.3': ('nist', 'sha512'),
        'sha256': ('', 'sha256'),
        'sha384': ('', 'sha384'),
        'sha512': ('', 'sha512'),
    }

    __cryptography_hashes__: dict[str, type[hashes.HashAlgorithm]] = {
        'sha256': hashes.SHA256,
        'sha384': hashes.SHA384,
        'sha512': hashes.SHA512,
    }

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.with_info_plain_validator_function(cls.discover),
            python_schema=core_schema.union_schema([
                core_schema.chain_schema([
                    core_schema.is_instance_schema(cls),
                ]),
                core_schema.chain_schema([
                    core_schema.is_instance_schema(str),
                    core_schema.with_info_plain_validator_function(cls.discover),
                ]),
            ]),
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
        value: str,
        info: pydantic.ValidationInfo
    ) -> Self:
        if value not in cls.__oid__mapping__:
            raise ValueError(f'Unknown digest algorithm: {value}')
        source, name = cls.__oid__mapping__[value]
        return cls(source, name, oid=value)

    def __init__(self, source: str, name: str, oid: str | None = None):
        self.source = source
        self.name = name
        self.oid = oid

    def digest(self, value: bytes) -> bytes:
        hasher = self.new()
        hasher.update(value)
        return hasher.digest()

    def hexdigest(self, value: bytes):
        return bytes.hex(self.digest(value))

    @overload
    def new(self) -> _hashlib.HASH: # type: ignore
        ...

    @overload
    def new(self, mode: Literal['cryptography']) -> hashes.Hash:
        ...

    def new(
        self,
        mode: Literal['stdlib', 'cryptography'] = 'stdlib',
    ) -> hashes.Hash | _hashlib.HASH: # type: ignore
        match mode:
            case 'cryptography':
                raise NotImplementedError
            case 'stdlib':
                return hashlib.new(self.name, usedforsecurity=True)

        raise ValueError(f'Unsupported hash: {self.name}')

    def __str__(self):
        return self.oid or self.name

    def __repr__(self):
        return f'<DigestAlgorithm: {self.name}>'