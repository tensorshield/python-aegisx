import asyncio
import functools
from typing import Any

import pydantic
from libcanonical.types import Base64

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import Undecryptable
from ._jsonwebkey import JSONWebKey
from ._jweheader import JWEHeader
from ._recipient import Recipient


class JWEGeneralSerialization(pydantic.BaseModel):
    protected: Base64 = pydantic.Field(
        default_factory=lambda: Base64(b'{}'),
        title="Protected",
        description=(
            "The `protected` member MUST be present and contain "
            "the value `BASE64URL(UTF8(JWE Protected Header))` "
            "when the JWE Protected Header value is non-empty; "
            "otherwise, it MUST be absent. These Header Parameter "
            "values are integrity protected."
        )
    )

    unprotected: dict[str, Any] = pydantic.Field(
        default_factory=dict,
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
        default_factory=Base64,
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

    plaintext: bytes = pydantic.Field(
        default_factory=bytes,
        exclude=True
    )

    _cek: JSONWebKey | None = pydantic.PrivateAttr(
        default=None
    )

    _alg: JSONWebAlgorithm | None = pydantic.PrivateAttr(
        default=None
    )

    _enc: JSONWebAlgorithm | None = pydantic.PrivateAttr(
        default=None
    )

    _epk: JSONWebKey | None = pydantic.PrivateAttr(
        default=None
    )

    @property
    def enc(self):
        return self._enc

    @functools.cached_property
    def header(self) -> JWEHeader:
        return JWEHeader.model_validate({
            **self.unprotected,
            **JWEHeader.model_validate_json(self.protected).model_dump(),
        })

    @pydantic.model_validator(mode='after')
    def validate_rfc7516(self):
        if not self.plaintext and not self.ciphertext:
            raise ValueError("Either the plaintext or the ciphertext is required.")

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
            protected = JWEHeader.model_validate_json(self.protected)
            protected_claims = set(protected.model_dump(exclude_defaults=True))
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
        if 'dir' in algorithms and len(self.recipients) > 1:
            raise ValueError(
                "The 'dir' algorithm can not be used with multiple "
                "recipients."
            )

        return self

    def add_recipient(
        self,
        key: JSONWebKey,
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        header: dict[str, Any]
    ):
        if self._alg is not None:
            raise ValueError(
                "Can not add multiple recipients when using direct "
                "encryption or direct key agreement."
            )
        if not self.has_cek():
            self.generate_cek(key, alg, enc)
        if enc != self.enc:
            raise ValueError(
                "All recipients must use the same encryption algorithm."
            )
        self.recipients.append(Recipient.new(key, alg, enc, header=header))
        if alg.is_direct():
            self._alg = alg
        return self.recipients[-1]

    def can_add_recipient(self):
        return not any([
            bool(self._epk),
            bool(self._alg)
        ])

    def generate_cek(self, key: JSONWebKey, alg: JSONWebAlgorithm, enc: JSONWebAlgorithm):
        if self._cek is not None:
            raise ValueError(
                "Can not generate a new Content Encryption Key (CEK) "
                "as its already declared."
            )
        self._enc = enc
        match alg.mode:
            case 'DIRECT_ENCRYPTION':
                self._cek = key
            case 'DIRECT_KEY_AGREEMENT':
                if not key.is_asymmetric():
                    raise TypeError(
                        "Direct Key Agreement can not be used with symmetric "
                        f"key of type {key.kty}."
                    )
                assert key.public is not None
                self._epk, private = key.epk()
                self._cek = key.derive_cek(alg, enc, private, key.public)
            case _:
                self._cek = JSONWebKey.cek(enc)

    def get_encrypted_cek(self, header: JWEHeader, ct: bytes):
        """Return a :class:`EncryptionResult` instance holding the per-recipient
        JWE Encrypted Key.
        """
        alg = header.alg or self.header.alg
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

    def has_cek(self):
        return bool(self._cek)

    def is_encrypted(self):
        return all([
            bool(self.ciphertext),
            bool(self.recipients),
            all([recipient.is_encrypted() for recipient in self.recipients])
        ])

    def set_content_encryption_key(
        self,
        cek: JSONWebKey
    ):
        if self._cek is not None:
            raise ValueError("A Content Encryption Key (CEK) is already supplied.")
        self._cek = cek

    async def decrypt(self, key: JSONWebKey, clear: bool = False) -> bytes:
        if not self.recipients:
            # If there are no recipients, an attacked might have sent the
            # plaintext (as our model accepts such a parameter) to trick
            # us into believing that is a valid JWE.
            raise Undecryptable
        recipient, self._cek = await self.decrypt_cek(key)
        self.plaintext = await self._cek.decrypt(
            EncryptionResult(
                alg=recipient.enc,
                ct=self.ciphertext,
                iv=self.iv,
                tag=self.tag,
                aad=self.protected.urlencode(),
            )
        )
        return self.plaintext

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
            if not recipient.might_decrypt(key, self.header):
                continue
            candidates.append(recipient)
        if len(candidates) > 1:
            raise NotImplementedError
        if len(candidates) == 0:
            raise NotImplementedError
        return candidates[0], cek or await candidates[0].decrypt(self, key)

    async def encrypt_cek(
        self,
        alg: JSONWebAlgorithm,
        key: JSONWebKey
    ):
        """Encrypt the Content Encryption Key (CEK) for the given
        recipient.
        """
        assert self._enc is not None
        assert self._cek is not None
        assert alg.mode not in {'DIRECT_ENCRYPTION', 'DIRECT_KEY_AGREEMENT'}
        return await key.encrypt(bytes(self._cek), alg=alg)

    async def finalize(self):
        """Encrypt the Content Encryption Key (CEK) for all recipients."""
        # Run this first so that all necessary artifacts are present e.g.
        # epk
        tasks: list[asyncio.Task[None]] = []
        for recipient in self.recipients:
            tasks.append(asyncio.create_task(recipient.finalize(self)))
        await asyncio.gather(*tasks)

        # Create the protected header first as its used as the
        # authenticated data in some encryption algorithms. Put
        # the "enc" claim in the protected header as it's used
        # shared by all recipients.
        assert self._cek is not None
        assert self._enc is not None
        protected = JWEHeader(
            alg=self._alg,
            enc=self._enc,
            epk=self._epk
        )
        if len(self.recipients) == 1:
            # If there is one recipient, move the recipient header
            # into the protected header. Clear the recipient
            # header to prevent duplicate claims.
            protected |= self.recipients[0].header
            self.recipients[0].header = JWEHeader()

        # Wipe all keys in the unprotected header that are
        # also in the protected keys.
        for k in protected.keys():
            self.unprotected.pop(k, None)

        # Encode the protected header to bytes.
        self.protected = Base64(protected)

        # Encrypt the content.
        result = await self._cek.encrypt(
            pt=self.plaintext,
            aad=self.protected.urlencode(),
            alg=self._enc
        )
        self.ciphertext = Base64(result)
        self.iv = Base64(result.iv)
        self.tag = Base64(result.tag)
        return self