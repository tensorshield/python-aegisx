import functools
from typing import Any
from typing import Awaitable

from aegisx.ext.jose.models.jwk import JSONWebKey
from aegisx.ext.jose.models.jwk import JSONWebKeyEdwardsCurvePrivate
from aegisx.ext.jose.models.jwk import JSONWebKeyEllipticCurvePrivate
from aegisx.ext.jose.models.jwk import JSONKeyRSAPrivate
from aegisx.ext.jose.models.jwk import JSONWebKeySR25519Private
from aegisx.ext.jose.models.jwk import SymmetricSigningKey


class JOSEBackend:
    """The base class for cryptographic backend implementations."""

    def sign_ecdsa(
        self,
        key: JSONWebKeyEllipticCurvePrivate
    ) -> Awaitable[bytes]:
        raise NotImplementedError

    def sign_eddsa(
        self,
        key: JSONWebKeyEdwardsCurvePrivate
    ) -> Awaitable[bytes]:
        raise NotImplementedError

    def sign_rsa(
        self,
        key: JSONKeyRSAPrivate
    ) -> Awaitable[bytes]:
        raise NotImplementedError

    def sign_sr25519(
        self,
        key: JSONWebKeySR25519Private
    ) -> Awaitable[bytes]:
        raise NotImplementedError

    def sign_symmetric(
        self,
        key: SymmetricSigningKey
    ) -> Awaitable[bytes]:
        raise NotImplementedError

    @functools.singledispatchmethod
    def sign(
        self,
        key: JSONWebKey,
        prehashed: bool = False
    ) -> bytes | Awaitable[bytes]:
        raise TypeError('The given key is not able to create signatures.')

    @sign.register
    def _(self, key: JSONWebKeyEllipticCurvePrivate,  *args: Any):
        return self.sign_ecdsa(key, *args)

    @sign.register
    def _(self, key: JSONWebKeyEdwardsCurvePrivate,  *args: Any):
        return self.sign_eddsa(key, *args)

    @sign.register
    def _(self, key: JSONKeyRSAPrivate,  *args: Any):
        return self.sign_rsa(key, *args)

    @sign.register
    def _(self, key: JSONWebKeySR25519Private,  *args: Any):
        return self.sign_sr25519(key, *args)

    @sign.register
    def _(self, key: SymmetricSigningKey,  *args: Any):
        return self.sign_symmetric(key, *args)