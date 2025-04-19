import asyncio
import json
import time
from collections import OrderedDict
from typing import overload
from typing import Any
from typing import Generic
from typing import Literal
from typing import TypeVar
from typing import Unpack

import pydantic
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64encode

from .models import JWEHeader
from .models import JSONWebKey
from .models import JSONWebToken
from .models import JWEGeneralSerialization
from .models import JWSCompactSerialization
from .models import JWSFlattenedSerialization
from .models import JWSGeneralSerialization
from .tokenkey import TokenKey
from .tokenrecipient import TokenRecipient
from .types import JSONWebAlgorithm
from .types import JWEHeaderDict
from .types import JWSHeaderDict
from .types import KeyManagementMode


T = TypeVar('T', default=JSONWebToken | bytes, bound=JSONWebToken | bytes)

SerializationMode = Literal['python', 'jose', 'json', 'auto']

SerializationFormat = Literal['compact', 'flattened', 'general']


class TokenBuilder(Generic[T]):
    SerializationFormat = SerializationFormat
    managed_claims: set[str] = set()

    _adapter: pydantic.TypeAdapter[T]
    _alg: JSONWebAlgorithm | None
    _audience: set[HTTPResourceLocator | str]
    _can_add_recipients: bool = True
    _can_add_signatures: bool = True
    _cek: JSONWebKey | None
    _claims: dict[str, Any]
    _compact: bool = False
    _content_type: str | None
    _enc: JSONWebAlgorithm | None
    _epk: JSONWebKey | None
    _encryption_mode: KeyManagementMode
    _issuer: HTTPResourceLocator | None
    _jws_encoder: pydantic.TypeAdapter[JWSGeneralSerialization[T] | JWSFlattenedSerialization[T] | JWSCompactSerialization[T]]
    _mode: Literal['python', 'jose', 'json']
    _format: Literal['compact', 'flattened', 'general']
    _payload: bytes | None
    _plaintext: bytes | None
    _protected: dict[str, Any]
    _recipients: OrderedDict[str, TokenRecipient]
    _signers: OrderedDict[str, TokenKey[JWSHeaderDict]]
    _unprotected: dict[str, Any]

    @property
    def plaintext(self):
        return self._plaintext

    @overload
    def __init__(
        self,
        types: type[T] = ...,
        *,
        compact: bool = ...,
        signers: list[JSONWebKey] | None = ...,
        autoinclude: set[str] | None = ...,
        replicate_claims: bool = False,
    ) -> None: ...

    # This second overload is for unsupported special forms (such as Annotated, Union, etc.)
    # Currently there is no way to type this correctly
    # See https://github.com/python/typing/pull/1618
    @overload
    def __init__(
        self,
        types: Any = ...,
        *,
        compact: bool = ...,
        signers: list[JSONWebKey] | None = ...,
        autoinclude: set[str] | None = ...,
        replicate_claims: bool = False,
    ) -> None: ...

    def __init__(
        self,
        types: Any = bytes,
        *,
        compact: bool = False,
        signers: list[JSONWebKey] | None = None,
        autoinclude: set[str] | None = None,
        replicate_claims: bool = False,
    ):
        self._adapter = pydantic.TypeAdapter(types)
        self._alg = None
        self._autoinclude = autoinclude or set()
        self._audience = set()
        self._cek = None
        self._compact = compact
        self._content_type = None
        self._claims = {}
        self._enc = None
        self._epk = None
        self._format = 'compact'
        self._issuer = None
        self._jws_encoder = pydantic.TypeAdapter(JWSGeneralSerialization | JWSFlattenedSerialization | JWSCompactSerialization)
        self._mode = 'jose'
        self._payload = None
        self._plaintext = None
        self._protected = {}
        self._recipients = OrderedDict()
        self._replicate_claims = replicate_claims
        self._signers = OrderedDict([
            (k.thumbprint('sha256'), TokenKey[JWSHeaderDict].fromkey(k))
            for k in (signers or [])]
        )
        self._unprotected = {}

    def audience(self, audience: set[str] | str):
        if isinstance(audience, str):
            audience = {audience}
        self._audience.update(map(HTTPResourceLocator.validate, audience))
        return self

    def compact(self):
        if len(self._signers) > 1:
            raise TypeError('Can not use compact encoding with multiple signers.')
        self._compact = True
        return self

    def encrypt(
        self,
        key: JSONWebKey,
        include: bool = False,
        x5t_sha256: str | None = None,
        **kwargs: Unpack[JWEHeaderDict]
    ):
        if not self._can_add_recipients:
            raise TypeError('No more recipients may be added.')
        if self._recipients and self._compact:
            raise TypeError('Can not use compact encoding with multiple signers.')
        alg = kwargs.get('alg') or key.alg
        enc = kwargs.get('enc')
        if alg is None:
            raise TypeError('The "alg" parameter is required.')
        if enc is None:
            raise TypeError('The "enc" parameter is required.')
        if self._enc is None:
            self.generate_cek(
                key=key,
                alg=JSONWebAlgorithm.validate(alg),
                enc=JSONWebAlgorithm.validate(enc)
            )

        t = key.thumbprint('sha256')
        recipient = self._recipients.get(t)
        if recipient is None:
            kwargs.update({'alg': alg, 'enc': enc})
            if x5t_sha256 is not None:
                kwargs['x5t#S256'] = x5t_sha256
            if include and key.public is not None:
                kwargs['jwk'] = key.public.model_dump(
                    exclude_defaults=True,
                    exclude_unset=True,
                    exclude_none=True
                )
            self._recipients[t] = TokenRecipient.fromkey(key, **kwargs)
        return self

    def generate_cek(self, key: JSONWebKey, alg: JSONWebAlgorithm, enc: JSONWebAlgorithm):
        if self._cek is not None:
            raise ValueError(
                "Can not generate a new Content Encryption Key (CEK) "
                "as its already declared."
            )
        self._enc = enc
        match alg.mode:
            case 'DIRECT_ENCRYPTION':
                self._alg = alg
                self._can_add_recipients = False
                self._cek = key
            case 'DIRECT_KEY_AGREEMENT':
                if not key.is_asymmetric():
                    raise TypeError(
                        "Direct Key Agreement can not be used with symmetric "
                        f"key of type {key.kty}."
                    )
                assert key.public is not None
                self._alg = alg
                self._can_add_recipients = False
                self._epk, private = key.epk()
                self._cek = key.derive_cek(alg, enc, private, key.public)
            case _:
                self._cek = JSONWebKey.cek(alg, enc)

    def issuer(self, iss: HTTPResourceLocator | str):
        if not isinstance(iss, HTTPResourceLocator):
            iss = HTTPResourceLocator.validate(iss)
        self._issuer = iss
        return self

    def payload(self, payload: bytes, cty: str | None = None):
        if self._claims:
            raise TypeError(
                'Can not set payload when a structured payload is specified.'
            )
        if cty is not None:
            self._content_type = cty
        self._payload = payload
        return self

    def replicate(self, header: JWEHeader):
        """Replicate public claims in the JWE Protected Header."""
        if self._replicate_claims:
            header.iss = self._claims.get('iss')
            header.aud = self._claims.get('aud')
            header.sub = self._claims.get('sub')

    def serialize(
        self,
        obj: JWEGeneralSerialization | JWSGeneralSerialization,
        mode: Literal['python', 'jose', 'json', 'auto'] = 'auto',
        syntax: SerializationFormat = 'compact',
        encode: bool = False
    ):
        match mode:
            case 'auto':
                return obj.model_dump_json(
                    context={'syntax': syntax, 'encode': encode},
                    exclude_defaults=True,
                    exclude_none=True,
                    exclude_unset=True
                )
            case 'jose':
                if encode:
                    raise TypeError(
                        'Can not set encode=True when using "jose" '
                        'serialization mode.'
                    )
                return obj
            case 'json':
                return obj.model_dump_json(
                    context={'syntax': syntax, 'encode': encode},
                    exclude_defaults=True,
                    exclude_none=True,
                    exclude_unset=True
                )
            case 'python':
                return obj.model_dump(
                    context={'syntax': syntax, 'encode': encode},
                    mode='json',
                    exclude_defaults=True,
                    exclude_none=True,
                    exclude_unset=True
                )

    def serialize_payload(self, payload: T) -> tuple[bytes, dict[str, Any]]:
        claims: dict[str, Any] = {}
        if isinstance(payload, JSONWebToken):
            claims['typ'] = self._content_type or 'jwt'
            encoded = bytes(payload)
        else:
            claims['cty'] = self._content_type or 'octet-stream'
            encoded = b64encode(bytes(payload))
        return encoded, claims

    def serialize_jwe(
        self,
        obj: dict[str, Any],
        mode: SerializationMode,
        encode: bool = False,
        syntax: SerializationFormat | None = None,
    ) -> str | bytes | dict[str, Any]:
        encoding = 'utf-8'
        if mode == 'auto' or syntax is None:
            syntaxes: list[SerializationFormat] = ['compact', 'flattened', 'general']
            flags = [
                len(obj['recipients']) == 1 and not obj.get('unprotected') and not bool(obj['recipients'][0].get('header')),
                len(obj['recipients']) == 1 and bool(obj['recipients'][0].get('header')),
                len(obj['recipients']) > 1
            ]
            syntax = syntaxes[flags.index(True)]
        if syntax == 'compact':
            encoding = 'ascii'
        match syntax:
            case 'compact':
                encoded = {
                    'protected': obj['protected'],
                    'encrypted_key': obj['recipients'][0].get('encrypted_key', ''),
                    'iv': obj['iv'],
                    'ciphertext': obj['ciphertext'],
                    'tag': obj['tag']
                }
                if mode in {'auto'}:
                    encoded = '{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}'.format(**encoded)
            case 'flattened':
                raise NotImplementedError(obj)
            case 'general':
                encoded = obj
                if mode in {'auto'}:
                    encoded = json.dumps(encoded)

        if isinstance(encoded, str) and encode:
            encoded = str.encode(encoded, encoding)
        return encoded

    def serialize_jws(
        self,
        obj: dict[str, Any],
        mode: SerializationMode,
        encode: bool = False,
        syntax: SerializationFormat | None = None,
    ) -> str | bytes | dict[str, Any]:
        encoding = 'utf-8'
        if mode == 'auto' or syntax is None:
            syntaxes: list[SerializationFormat] = ['compact', 'flattened', 'general']
            flags = [
                len(obj['signatures']) == 1 and not obj.get('header'),
                len(obj['signatures']) == 1 and bool(obj['signatures'][0].get('header')),
                len(obj['signatures']) > 1
            ]
            syntax = syntaxes[flags.index(True)]
        if syntax == 'compact':
            encoding = 'ascii'
        match syntax:
            case 'compact':
                encoded = {
                    'protected': obj['signatures'][0]['protected'],
                    'payload': obj['payload'],
                    'signature': obj['signatures'][0]['signature']
                }
                if mode in {'auto'}:
                    encoded = '{protected}.{payload}.{signature}'.format(**encoded)
            case 'flattened':
                encoded = {
                    'protected': obj['signatures'][0]['protected'],
                    'payload': obj['payload'],
                    'signature': obj['signatures'][0]['signature']
                }
                if obj['signatures'][0].get('header'):
                    encoded['header'] = obj['signatures'][0]['header']
                if mode in {'auto'}:
                    encoded = json.dumps(encoded)
            case 'general':
                encoded = obj
                if mode in {'auto'}:
                    encoded = json.dumps(encoded)

        if isinstance(encoded, str) and encode:
            encoded = str.encode(encoded, encoding)
        return encoded

    def sign(
        self,
        key: JSONWebKey,
        include: bool = False,
        x5t_sha256: str | None = None,
        **kwargs: Unpack[JWSHeaderDict]
    ):
        if self._signers and self._compact:
            raise TypeError('Can not use compact encoding with multiple signers.')
        t = key.thumbprint('sha256')
        signer = self._signers.get(t)
        if signer is None:
            if x5t_sha256 is not None:
                kwargs['x5t#S256'] = x5t_sha256
            if include and key.public is not None:
                kwargs['jwk'] = key.public.model_dump(
                    exclude_defaults=True,
                    exclude_unset=True,
                    exclude_none=True
                )
            signer = TokenKey[JWSHeaderDict].fromkey(key, **kwargs)
            if signer.protected.get('alg') is None:
                raise TypeError('The "alg" parameter is required.')
            self._signers[t] = signer
        return self

    def update(self, claims: dict[str, Any] | None = None, /, **kwargs: Any):
        if self._payload:
            raise TypeError(
                'Can not set claims when a binary payload is specified.'
            )
        self._claims.update(claims or {})
        self._claims.update({k: v for k, v in kwargs.items() if v is not None})
        return self

    @overload
    async def build(self, mode: Literal['python'], syntax: SerializationFormat = ...) -> dict[str, Any]:
        ...

    @overload
    async def build(self, mode: Literal['json'], syntax: SerializationFormat = ...) -> JWEGeneralSerialization | JWSGeneralSerialization:
        ...

    @overload
    async def build(self, mode: Literal['jose'], syntax: SerializationFormat = ...) -> str:
        ...

    @overload
    async def build(self) -> str:
        ...

    @overload
    async def build(self, mode: SerializationMode = ..., syntax: SerializationFormat = ...) -> str:
        ...

    async def build(
        self,
        mode: Literal['python', 'jose', 'json', 'auto'] = 'auto',
        syntax: SerializationFormat = 'compact'
    ) -> bytes | str | dict[str, Any] | JWEGeneralSerialization | JWSGeneralSerialization:
        now = int(time.time())
        for claim in self._autoinclude:
            match claim:
                case 'iat':
                    self.update(iat=now)
                case 'nbf':
                    self.update(nbf=now)
                case _:
                    raise NotImplementedError(
                        f'Claim "{claim}" is not a valid argument for autoinclude.'
                    )
        claims = self._claims or {}
        if self._audience:
            claims['aud'] = self._audience
        if self._issuer:
            claims['iss'] = self._issuer
        if not claims and not self._payload:
            raise TypeError('Can not build an empty object.')
        payload = self._adapter.validate_python(claims or self._payload)
        if isinstance(payload, JSONWebToken):
            if self._audience:
                payload.aud = self._audience
            if self._issuer:
                payload.iss = self._issuer
        return await self.build_jose(payload, mode=mode, syntax=syntax) # type: ignore

    async def build_jose(
        self,
        payload: T,
        mode: SerializationMode,
        syntax: SerializationFormat
    ):
        if not self._signers and not self._recipients:
            # If there are no signers, we are trying to build the payload
            # object.
            return self._adapter.validate_python(payload)

        encoded, claims = self.serialize_payload(payload)
        token: dict[str, Any] | JWEGeneralSerialization | JWSGeneralSerialization | None = None
        if self._content_type is not None:
            claims['cty'] = self._content_type
        if self._signers:
            token = {
                'payload': encoded,
                'signatures': []
            }
            for signer in self._signers.values():
                token['signatures'].append(await signer.sign(token['payload'], claims))
            token['payload'] = bytes.decode(token['payload'], 'ascii')
            if not self._recipients:
                return self.serialize_jws(token, mode=mode, syntax=syntax)

        if self._recipients:
            assert self._cek
            tasks: list[asyncio.Task[None]] = []
            for recipient in self._recipients.values():
                tasks.append(asyncio.create_task(recipient.encrypt(self._cek)))
            await asyncio.gather(*tasks)

            protected = JWEHeader(
                alg=self._alg,
                enc=self._enc,
                epk=self._epk
            )
            if len(self._recipients) == 1:
                # If there is one recipient, move the recipient header
                # into the protected header. Clear the recipient
                # header to prevent duplicate claims.
                assert self._enc
                recipient = [*self._recipients.values()][0]
                protected = recipient.header | protected
                protected.typ = 'application/jose'
                recipient.header = JWEHeader()
                assert protected.alg
            else:
                protected.typ = 'application/jose+json'

            # Encrypt the payload or the JWS.
            pt = payload
            if isinstance(pt, bytes):
                protected.cty = 'application/octet-stream'
            if isinstance(payload, JSONWebToken):
                pt = bytes(payload)
                protected.typ = 'JWT'
                if token is not None:
                    protected.cty = "JWT"
                self.replicate(protected)
            if token is not None:
                pt = self.serialize_jws(token, mode='auto', encode=True)
                assert isinstance(pt, bytes)

            if self._content_type:
                protected.cty = self._content_type
            assert isinstance(pt, bytes)
            self._plaintext = pt
            result = await self._cek.encrypt(
                pt=pt,
                aad=b64encode(bytes(protected)),
                alg=self._enc
            )
            token = {
                'protected': b64encode(bytes(protected), encoder=str),
                'ciphertext': b64encode(result.ct, encoder=str),
                'iv': b64encode(result.iv, encoder=str),
                'tag': b64encode(result.tag, encoder=str),
                'recipients': []
            }
            for recipient in self._recipients.values():
                token['recipients'].append(recipient.as_recipient())
        assert token
        return self.serialize_jwe(token, mode=mode, syntax=syntax)