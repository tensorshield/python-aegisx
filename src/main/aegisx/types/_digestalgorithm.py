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
        '2.16.840.1.101.3.4.2.1'    : ('oid', 'sha256'),
        '2.16.840.1.101.3.4.2.2'    : ('oid', 'sha384'),
        '2.16.840.1.101.3.4.2.3'    : ('oid', 'sha512'),
        '2.16.840.1.101.3.4.2.8'    : ('oid', 'sha3_256'),
        '2.16.840.1.101.3.4.2.9'    : ('oid', 'sha3_384'),
        '2.16.840.1.101.3.4.2.10'   : ('oid', 'sha3_512'),
        '1.3.6.1.4.1.1722.12.2.1.16': ('oid', 'blake2b512'),
        '1.3.6.1.4.1.1722.12.2.2.8' : ('oid', 'blake2s256'),
        'sha256'                    : ('', 'sha256'),
        'sha384'                    : ('', 'sha384'),
        'sha512'                    : ('', 'sha512'),
        'sha3_256'                  : ('', 'sha3_256'),
        'sha3_384'                  : ('', 'sha3_384'),
        'sha3_512'                  : ('', 'sha3_512'),
        'blake2b512'                : ('', 'blake2b512'),
        'blake2s256'                : ('', 'blake2s256'),
    }

    __cryptography_hashes__: dict[str, tuple[type[hashes.HashAlgorithm], list[Any]]] = {
        'sha256'    : (hashes.SHA256, []),
        'sha384'    : (hashes.SHA384, []),
        'sha512'    : (hashes.SHA512, []),
        'sha3_256'  : (hashes.SHA3_256, []),
        'sha3_384'  : (hashes.SHA3_384, []),
        'sha3_512'  : (hashes.SHA3_512, []),
        'blake2b512': (hashes.BLAKE2b, [64]),
        'blake2s256': (hashes.BLAKE2s, [32])
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
            raise ValueError(f'Unknown digest algorithm: {value}')
        source, name = cls.__oid__mapping__[value]
        return cls(source, name, oid=value)

    def __init__(self, source: str, name: str, oid: str | None = None):
        self.source = source
        self.name = name
        self.oid = oid

    def digest(self, value: bytes) -> bytes:
        h = hashes.Hash(self.hash('cryptography'))
        h.update(value)
        return h.finalize()

    @overload
    def hash(self) -> str: # type: ignore
        ...

    @overload
    def hash(self, mode: Literal['cryptography']) -> hashes.HashAlgorithm:
        ...

    def hash(
        self,
        mode: Literal['stdlib', 'cryptography'] = 'stdlib',
    ) -> hashes.HashAlgorithm | str: # type: ignore
        match mode:
            case 'cryptography':
                HashAlgorithm, args = self.__cryptography_hashes__[self.name]
                return HashAlgorithm(*args)
            case 'stdlib':
                return self.name

        raise ValueError(f'Unsupported hash: {self.name}')

    def __str__(self):
        return self.name

    def __repr__(self):
        return f'<DigestAlgorithm: {self.name} (oid: {self.oid})>'