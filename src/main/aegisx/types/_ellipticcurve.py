import functools
from typing import Any
from typing import Literal
from typing import Self
from typing import Union

from cryptography.x509 import ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric import ec
import pydantic
from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler

from ._oidmapped import OIDMapped


class EllipticCurve(OIDMapped):
    __module__: str = 'aegisx.types'
    __oid__mapping__ = {
        ec.EllipticCurveOID.SECP256R1.dotted_string         : ('oid', 'P-256'),
        ec.EllipticCurveOID.SECP384R1.dotted_string         : ('oid', 'P-384'),
        ec.EllipticCurveOID.SECP521R1.dotted_string         : ('oid', 'P-512'),
        ec.EllipticCurveOID.SECP256K1.dotted_string         : ('oid', 'P-256K'),
        str(ec.SECP256R1.name)                              : ('name', 'P-256'),
        str(ec.SECP256K1.name)                              : ('name', 'P-256K'),
        str(ec.SECP384R1.name)                              : ('name', 'P-384'),
        str(ec.SECP521R1.name)                              : ('name', 'P-512'),
        '1.3.101.110'                                       : ('oid', 'X25519'),
        '1.3.101.111'                                       : ('oid', 'X448'),
        '1.3.101.112'                                       : ('oid', 'Ed25519'),
        '1.3.101.113'                                       : ('oid', 'Ed448'),
        'P-256'                                             : ('literal', 'P-256'),
        'P-384'                                             : ('literal', 'P-384'),
        'P-521'                                             : ('literal', 'P-521'),
        'P-256K'                                            : ('literal', 'P-256K'),
        'X25519'                                            : ('literal', 'X25519'),
        'X448'                                              : ('literal', 'X448'),
        'Ed25519'                                           : ('literal', 'Ed25519'),
        'Ed448'                                             : ('literal', 'Ed448'),

        # These are non-standardized names invented by me.
        ec.EllipticCurveOID.SECP192R1.dotted_string         : ('oid', 'P-192'),
        ec.EllipticCurveOID.SECP224R1.dotted_string         : ('oid', 'P-224'),
        ec.EllipticCurveOID.BRAINPOOLP256R1.dotted_string   : ('oid', 'B-256'),
        ec.EllipticCurveOID.BRAINPOOLP384R1.dotted_string   : ('oid', 'B-384'),
        ec.EllipticCurveOID.BRAINPOOLP512R1.dotted_string   : ('oid', 'B-512'),
        str(ec.SECP192R1.name)                              : ('name', 'P-192'),
        str(ec.SECP224R1.name)                              : ('name', 'P-224'),
        str(ec.BrainpoolP256R1.name)                        : ('name', 'B-256'),
        str(ec.BrainpoolP384R1.name)                        : ('name', 'B-384'),
        str(ec.BrainpoolP512R1.name)                        : ('name', 'B-512'),
        'P-192'                                             : ('literal', 'P-192'),
        'P-224'                                             : ('literal', 'P-224'),
        'B-256'                                             : ('literal', 'B-256'),
        'B-384'                                             : ('literal', 'B-384'),
        'B-512'                                             : ('literal', 'B-512'),
        'Sr25519'                                           : ('literal', 'Sr25519'),
    }

    __cryptography_curves__: dict[str, type[ec.EllipticCurve]] = {
        'P-192'     : ec.SECP192R1,
        'P-224'     : ec.SECP224R1,
        'P-256'     : ec.SECP256R1,
        'P-256K'    : ec.SECP256K1,
        'P-384'     : ec.SECP384R1,
        'P-521'     : ec.SECP521R1,
        'B-256'     : ec.BrainpoolP256R1,
        'B-384'     : ec.BrainpoolP384R1,
        'B-512'     : ec.BrainpoolP512R1,
    }

    @functools.cached_property
    def signing_algorithm(self) -> Literal['ECDSA', 'EdDSA', 'SrDSA', None]:
        if self.curve_class is not None:
            return 'ECDSA'
        elif self._name in {'Ed448', 'Ed25519'}:
            return 'EdDSA'
        elif self._name == 'Sr25519':
            return 'SrDSA'
        else:
            # The remainder should be X448 or X25519, which can not
            # be used for signing.
            assert self._name in {'X448', 'X25519'}
            return None

    @functools.cached_property
    def curve_class(self):
        try:
            return self.__cryptography_curves__[self._name]
        except KeyError:
            return None

    @functools.cached_property
    def name(self):
        try:
            return self.__source_mapping__[('name', self._name)]
        except KeyError:
            return None

    @functools.cached_property
    def oid(self):
        try:
            return self.__source_mapping__[('oid', self._name)]
        except KeyError:
            return None

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.no_info_plain_validator_function(cls.new),
            python_schema=core_schema.no_info_plain_validator_function(cls.new),
            serialization=core_schema.plain_serializer_function_ser_schema(cls.serialize, info_arg=True),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _: CoreSchema,
        handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(
            core_schema.str_schema(
                serialization=core_schema.plain_serializer_function_ser_schema(
                    cls.serialize,
                    info_arg=True
                )
            )
        )

    @classmethod
    def new(
        cls,
        value: Union[
            Self,
            str,
            ec.EllipticCurve,
            ObjectIdentifier
        ]
    ) -> Self:
        if isinstance(value, cls):
            return value
        elif isinstance(value, ObjectIdentifier):
            value = value.dotted_string
        elif isinstance(value, ec.EllipticCurve):
            value = value.name
        assert isinstance(value, str)
        if value not in cls.__oid__mapping__:
            raise ValueError(f'Unknown curve: {value}')
        source, name = cls.__oid__mapping__[value]
        return cls(source, name, alias=value)

    def __init__(self, source: str, name: str, alias: str | None = None):
        self._source = source
        self._name = name
        self._alias = alias

    def can_sign(self):
        """Return ``True`` if the curve can be used with digital signature
        algorithms.
        """
        return self.signing_algorithm is not None

    def serialize(
        self,
        info: pydantic.SerializationInfo
    ):
        return self._name

    def __str__(self):
        return self._name

    def __repr__(self):
        return f'<Curve: {self._name} (input: {self._alias}, name: {self.name}, oid: {self.oid})>'