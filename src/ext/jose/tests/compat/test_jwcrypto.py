import json
from typing import Any
from typing import Awaitable

import pytest
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from libcanonical.utils.encoding import b64encode_json

from aegisx.ext.jose.testing.compat import *
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose.types import JSONWebAlgorithm


UNSUPPORTED_ALGORITHMS: set[str] = {
    'RSA-OAEP-384',
    'RSA-OAEP-512',
}

UNSUPPORTED_CURVES: set[str] = {'Sr25519', 'P-256K'}


@pytest.fixture
def jwe_factory():
    async def f(
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        recipients: list[JSONWebKey],
        payload: dict[str, Any] | bytes
    ) -> str:
        if alg in UNSUPPORTED_ALGORITHMS:
            pytest.skip(f"{alg} is not supported by jwcrypto")
        if isinstance(payload, dict):
            payload = b64encode_json(payload)
        protected: dict[str, Any] = {}
        if len(recipients) == 1:
            protected = {'alg': alg, 'enc': enc}
        jwe = JWE(plaintext=payload, protected=json.dumps(protected))
        for recipient in recipients:
            header: dict[str, Any] = {}
            if len(recipients) > 1:
                header = {'alg': alg, 'enc': enc}
            if recipient.crv:
                header['crv'] = recipient.crv
            if recipient.crv in UNSUPPORTED_CURVES:
                pytest.skip(f"{recipient.crv} is not supported by jwcrypto")
            jwk = JWK.from_json(recipient.model_dump_json(exclude_none=True)) # type: ignore
            jwe.add_recipient(jwk, header=header) # type: ignore
        return jwe.serialize(compact=len(recipients) == 1), payload # type: ignore

    return f


@pytest.fixture
def decrypt_jwe():
    async def f(serialized: bytes, recipients: list[JSONWebKey]):
        jwe = JWE.from_jose_token(serialized)
        for recipient in recipients:
            if recipient.alg in UNSUPPORTED_ALGORITHMS:
                pytest.skip(f"{recipient.alg} is not supported by jwcrypto")
            if recipient.crv in UNSUPPORTED_CURVES:
                pytest.skip(f"{recipient.crv} is not supported by jwcrypto")
            jwk = JWK.from_json(recipient.model_dump_json())  # type: ignore
            jwe.decrypt(jwk) # type: ignore
        return jwe.plaintext

    return f


@pytest.fixture
def jws_factory():
    async def f(
        alg: JSONWebAlgorithm,
        signers: list[JSONWebKey],
        payload: dict[str, Any] | bytes
    ) -> Awaitable[str]:
        if isinstance(payload, dict):
            payload = str.encode(json.dumps(payload), 'utf-8')
        jws = JWS(payload=payload)
        for signer in signers:
            if signer.crv in UNSUPPORTED_CURVES:
                pytest.skip(f"{signer.crv} is not supported by jwcrypto")
            jwk = JWK.from_json(signer.model_dump_json()) # type: ignore
            jws.add_signature(jwk, alg=signer.alg, protected={'alg': signer.alg}) # type: ignore
        return jws.serialize(compact=len(signers) == 1) # type: ignore
    return f


@pytest.fixture
def jws_verify():
    async def f(alg: JSONWebAlgorithm, signers: list[JSONWebKey], obj: str):
        assert isinstance(obj, str), "string expected"
        jws = JWS()
        jws.deserialize(obj) # type: ignore
        for signer in signers:
            if signer.crv in UNSUPPORTED_CURVES:
                pytest.skip(f"{signer.crv} is not supported by jwcrypto")
            jwk = JWK.from_json(signer.model_dump_json()) # type: ignore
            jws.verify(jwk) # type: ignore

        return True

    return f