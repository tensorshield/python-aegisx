from typing import Any

import pydantic
from libcanonical.types import Base64

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JWECompactEncoded
from aegisx.ext.jose.types import Undecryptable
from .jwk import JSONWebKey
from ._jweheader import JWEHeader
from ._recipient import Recipient


class JWEGeneralSerialization(pydantic.BaseModel):
    protected: JWEHeader = pydantic.Field(
        default_factory=JWEHeader,
        title="Protected",
        description=(
            "The `protected` member MUST be present and contain "
            "the value `BASE64URL(UTF8(JWE Protected Header))` "
            "when the JWE Protected Header value is non-empty; "
            "otherwise, it MUST be absent. These Header Parameter "
            "values are integrity protected."
        )
    )

    unprotected: JWEHeader = pydantic.Field(
        default_factory=JWEHeader,
        title="Header",
        description=(
            "The `unprotected` member MUST be present and contain "
            "the value JWE Shared Unprotected Header when the JWE "
            "Shared Unprotected Header value is non-empty; otherwise, "
            "it MUST be absent.  This value is represented as an "
            "unencoded JSON object, rather than as a string. These "
            "Header Parameter values are not integrity protected."
        )
    )

    iv: Base64 = pydantic.Field(
        default_factory=Base64,
        title="Initialization Vector (IV)",
        description=(
            "The `iv` member MUST be present and contain the value "
            "`BASE64URL(JWE Initialization Vector)` when the JWE "
            "Initialization Vector value is non-empty; otherwise, "
            "it MUST be absent."
        )
    )

    aad: Base64 = pydantic.Field(
        default_factory=Base64,
        title="Additional Authenticated Data (AAD)",
        description=(
            "The `aad` member MUST be present and contain the value "
            "`BASE64URL(JWE AAD))` when the JWE AAD value is non-empty; "
            "otherwise, it MUST be absent.  A JWE AAD value can be "
            "included to supply a base64url-encoded value to be integrity "
            "protected but not encrypted."
        )
    )

    ciphertext: Base64 = pydantic.Field(
        default=...,
        title="Ciphertext",
        description=(
            "The `ciphertext` member MUST be present and "
            "contain the value `BASE64URL(JWE Ciphertext)`."
        )
    )

    tag: Base64 = pydantic.Field(
        default_factory=Base64,
        title="Tag",
        description=(
            "The `tag` member MUST be present and contain the "
            "value `BASE64URL(JWE Authentication Tag)` when the "
            "JWE Authentication Tag value is non-empty; otherwise, "
            "it MUST be absent."
        )
    )

    recipients: list[Recipient] = pydantic.Field(
        default_factory=list,
        title="Recipients",
        description=(
            "The `recipients` member value MUST be an array of JSON objects. "
            "Each object contains information specific to a single recipient. "
            "This member MUST be present with exactly one array element per "
            "recipient, even if some or all of the array element values are the "
            "empty JSON object `{}` (which can happen when all Header Parameter "
            "values are shared between all recipients and when no encrypted key "
            "is used, such as when doing Direct Encryption)"
        )
    )

    @property
    def algorithms(self):
        values: set[str] = {
            x.header.alg for x in self.recipients
            if x.header.alg
        }
        if self.unprotected.alg: # pragma: no cover
            values.add(self.unprotected.alg)
        if self.protected.alg:
            values.add(self.protected.alg)
        return values

    @property
    def header(self):
        return self.unprotected | self.protected

    @property
    def headers(self) -> tuple[JWEHeader, JWEHeader, list[JWEHeader]]:
        return (
            self.protected,
            self.header,
            [x.header for x in self.recipients]
        )

    @pydantic.model_validator(mode='before')
    @classmethod
    def preprocess(cls, values: dict[str, Any] | JWECompactEncoded | Any):
        if isinstance(values, str):
            values = JWECompactEncoded.validate(values)
        if isinstance(values, JWECompactEncoded):
            values = values.dict()
        return values

    @pydantic.model_validator(mode='after')
    def validate_rfc7516(self):
        # The Header Parameter values used when creating or validating per-
        # recipient ciphertext and Authentication Tag values are the union of
        # the three sets of Header Parameter values that may be present: (1)
        # the JWE Protected Header represented in the "protected" member, (2)
        # the JWE Shared Unprotected Header represented in the "unprotected"
        # member, and (3) the JWE Per-Recipient Unprotected Header represented
        # in the "header" member of the recipient's array element.  The union
        # of these sets of Header Parameters comprises the JOSE Header.  The
        # Header Parameter names in the three locations MUST be disjoint.
        claims: set[str] = set(self.unprotected.keys())
        if self.protected:
            protected_claims = set(self.protected.model_dump(exclude_defaults=True))
            unprotected_claims = set(self.unprotected.keys())
            conflicting = protected_claims & unprotected_claims
            if conflicting:
                raise ValueError(
                    "The header parameters in the protected and unprotected "
                    "header must be disjoint."
                )
            claims.update(protected_claims)

        algorithms: set[str] = set()
        encryption: set[str] = set()
        for recipient in self.recipients:
            if bool(claims & set(recipient.header.keys())):
                raise ValueError(
                    "The header parameters in the protected, unprotected "
                    "and recipient header must be disjoint."
                )
            if recipient.header.alg:
                algorithms.add(recipient.header.alg)
            if recipient.header.enc:
                encryption.add(recipient.header.enc)
            recipient.add_to_jwe(self)

        if len(encryption) > 1:
            raise ValueError(
                "All recipients must use the same content encryption "
                "algorithm."
            )

        # The 'dir' (direct) algorithm cannot be used in a
        # multi-recipient JWE where other recipients use key-wrapping
        # or key-agreement algorithms  (e.g., RSA-OAEP, ECDH-ES),
        # because 'dir' uses the content encryption key (CEK) directly
        # without wrapping it, while other algorithms require the CEK
        # to be encrypted per recipient. Mixing these approaches is not
        # supported by the JWE specification (RFC 7516). Use separate JWE 
        # messages if different key management methods are needed.
        if bool({'dir', 'ECDH-ES'} & algorithms) and len(self.recipients) > 1:
            raise ValueError(
                "The 'dir' algorithm can not be used with multiple "
                "recipients."
            )

        if not self.algorithms:
            raise ValueError(
                'The "alg" Header Parameter was not present in either '
                'the protected, unprotected and recipient headers.'
            )

        return self

    def get_encrypted_cek(self, header: JWEHeader, ct: bytes):
        """Return a :class:`EncryptionResult` instance holding the per-recipient
        JWE Encrypted Key.
        """
        alg = header.alg or self.protected.alg or self.unprotected.alg
        assert alg is not None, (
            "Missing `alg` claim was not detected during serialization or "
            "object construction."
        )
        return EncryptionResult(
            alg=alg,
            ct=ct,
            iv=header.iv or self.header.iv,
            aad=b'',
            tag=header.tag or self.header.tag,
            epk=(header.epk or self.header.epk),
            apu=(header.apu or self.header.apu),
            apv=(header.apv or self.header.apv)
        )

    async def decrypt(self, key: JSONWebKey, clear: bool = False) -> tuple[JWEHeader, bytes]:
        if not self.recipients:
            # If there are no recipients, an attacked might have sent the
            # plaintext (as our model accepts such a parameter) to trick
            # us into believing that is a valid JWE.
            raise Undecryptable
        recipient, self._cek = await self.decrypt_cek(key)
        result = await self._cek.decrypt(
            EncryptionResult(
                alg=recipient.enc,
                ct=self.ciphertext,
                iv=self.iv,
                tag=self.tag,
                aad=self.protected.encoded,
            )
        )
        return (self.unprotected | recipient.header) | self.protected, result # type: ignore

    async def decrypt_cek(self, key: JSONWebKey):
        """Decrypt the Content Encryption Key (CEK) using the given
        Key Encryption Key (KEK).
        """
        candidates: list[Recipient] = []
        cek = None
        for recipient in self.recipients:
            if recipient.alg in {'dir', 'ECDH-ES'}:
                # In this case the key is the CEK and since the
                # dir algorithm can not be used with multiple
                # recipients, we can break early.
                cek = key
                if recipient.alg.mode == 'DIRECT_KEY_AGREEMENT':
                    # In direct key agreement mode, the CEK is the
                    # derived key.
                    cek = recipient.derive(key)
                candidates.append(recipient)
                break
            if not recipient.might_decrypt(key, self.unprotected | self.protected):
                continue
            candidates.append(recipient)
        if len(candidates) == 0:
            raise Undecryptable
        return candidates[0], cek or await candidates[0].decrypt(self, key)