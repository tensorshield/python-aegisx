from typing import Any

import pytest
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from jwcrypto.common import InvalidJWEOperation
from libcanonical.utils.encoding import b64encode_json

from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.testing.compat import *


UNSUPPORTED_ALGORITHMS: set[str] = {
    'RSA-OAEP-384',
    'RSA-OAEP-512',
}


UNSUPPORTED_CURVES: set[str] = {'Sr25519'}


@pytest.fixture
def supported_curves():
    return {'P-256', 'P-384', 'P-521', 'Ed448', 'Ed25519', 'X448', 'X25519'}


@pytest.fixture
def jws_verify():
    async def f(
        alg: JSONWebAlgorithm,
        signers: list[JSONWebKey],
        serialized: str
    ):
        if set([s.crv for s in signers]) & UNSUPPORTED_CURVES:
            pytest.skip(f"Curve is not supported by jwcrypto")
        jws = JWS.from_jose_token(serialized) # type: ignore
        return all([jws.verify(JWK.from_json(k.model_dump_json()), k.alg) for k in signers]) # type: ignore

    return f

@pytest.fixture
def jwe_factory():
    async def factory(
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm | None,
        signers: list[JSONWebKey],
        payload: dict[str, Any] | bytes
    ) -> str:
        if isinstance(payload, dict):
            payload = b64encode_json(payload)
        protected: dict[str, Any] = {}
        if len(signers) == 1:
            protected.update({
                'alg': alg,
            })
            if enc is not None:
                protected['enc'] = enc
            if signers[0].crv:
                protected['crv'] = signers[0].crv
        t = JWE(
            plaintext=payload,
            protected=protected # type: ignore
        )
        for signer in signers:
            jwk = JWK.from_json(signer.model_dump_json(exclude_defaults=True)) # type: ignore
            assert jwk.get('crv') == signer.crv # type: ignore
            if signer.alg in UNSUPPORTED_ALGORITHMS:
                pytest.skip(f"Algorithm not supported: {signer.alg}")
            try:
                header: dict[str, Any] = {}
                if len(signers) > 1:
                    header.update({'alg': alg})
                    if enc is not None:
                        header['enc'] = enc
                t.add_recipient(jwk, header) # type: ignore
            except InvalidJWEOperation as e:
                if e.args[0] != 'Algorithm not allowed':
                    raise
                pytest.skip(f"Algorithm not supported: {alg}")
        return t.serialize(compact=len(signers) == 1), payload # type: ignore

    return factory


@pytest.fixture
def decrypt_jwe():
    async def f(serialized: str, keys: list[JSONWebKey]):
        key = keys[0]
        if key.alg in UNSUPPORTED_ALGORITHMS:
            pytest.skip(f"Algorithm not supported: {key.alg}")
        jwk = JWK.from_json(key.model_dump_json(exclude={'key_ops'})) # type: ignore
        jwe = JWE.from_jose_token(serialized)
        jwe.decrypt(jwk) # type: ignore
        return jwe.plaintext

    return f


@pytest.fixture
def jws_factory():
    async def f(alg: JSONWebAlgorithm, signers: list[JSONWebKey], claims: dict[str, Any]) -> str:
        jws = JWS(payload=b64encode_json(claims))
        protected: dict[str, Any] = {}
        if len(signers) == 1:
            protected = {'alg': signers[0].alg}
        for signer in signers:
            if signer.crv in UNSUPPORTED_CURVES:
                pytest.skip(f"{signer.crv} is not supported by jwcrypto")
            jwk = JWK.from_json(signer.model_dump_json()) # type: ignore
            jws.add_signature(jwk, alg=signer.alg, protected=protected) # type: ignore
        return jws.serialize(compact=len(signers) == 1) # type: ignore
    return f