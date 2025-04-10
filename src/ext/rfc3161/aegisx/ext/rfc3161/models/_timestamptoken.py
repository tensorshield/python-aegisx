from typing import Any
from typing import Literal

import pydantic
from libcanonical.types import Base64
from libcanonical.types import HTTPResourceLocator
from pyasn1.codec.der import encoder

from aegisx.types import PlainBase64
from aegisx.ext.rfc3161.types import TimeStampResponse
from aegisx.ext.rfc3161.utils import digest_algorithm_name
from ._signature import Signer



class TimestampToken(pydantic.BaseModel):
    alg: Literal['sha256', 'sha384', 'sha512'] = pydantic.Field(
        default=...,
        title="Digest algorithm",
        description=(
            "The algorithm that was used to calculate the content "
            "hash."
        )
    )

    tsa: HTTPResourceLocator = pydantic.Field(
        default=...,
        title=(
            "The server URL of the Time Stamp Authority (TSA)."
        )
    )

    dig: Base64 = pydantic.Field(
        default=...,
        title="Digest",
        description=(
            "The digest over which the timestamp signature was "
            "obtained."
        )
    )

    signature: Signer = pydantic.Field(
        default=...,
    )

    der: PlainBase64 = pydantic.Field(
        default=...,
        title="Time Stamp Token (TST), DER-encoded"
    )

    @pydantic.model_serializer(mode='plain')
    def serialize(self):
        return str(self.der)

    @classmethod
    def fromresponse(
        cls,
        response: TimeStampResponse,
        url: str,
        digest: bytes
    ):
        tst = response.time_stamp_token
        message_imprint = tst.tst_info.message_imprint
        value: dict[str, Any] = {
            'tsa': url,
            'dig': Base64(digest),
            'der': PlainBase64(encoder.encode(tst)) # type: ignore
        }
        if str(tst.content['contentInfo']['contentType']) != '1.2.840.113549.1.9.16.1.4':
            raise ValueError("not a Time Stamp Token (TST)")
        alg_oid = str(message_imprint.hash_algorithm[0])
        value['alg'] = digest_algorithm_name(alg_oid)
        if digest != bytes(message_imprint.hashed_message):
            raise ValueError(
                "the digest returned by the TSA does not match our digest."
            )

        value['signature'] = Signer.model_validate(tst.content['signerInfos'][0])
        return cls.model_validate(value)
