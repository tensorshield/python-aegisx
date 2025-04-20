from typing import cast
from typing import Any

import pydantic
from libcanonical.types import DomainName
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64encode
from libcanonical.utils.encoding import b64decode_json

from aegisx.ext.jose.types import JSONWebKeySetURL


class JOSEHeader(pydantic.BaseModel):

    @pydantic.model_validator(mode='before')
    def preprocess(cls, value: Any):
        if value and isinstance(value, str):
            value = {**b64decode_json(value), 'encoded': value} # type: ignore
        return value

    @pydantic.field_validator('crit', mode='before', check_fields=False)
    @classmethod
    def validate_crit(
        cls,
        value: list[str] | None,
        info: pydantic.ValidationInfo
    ):
        ctx = cast(dict[str, Any], info.context or {})
        if ctx.get('strict', True) and value is not None:
            known_claims = set([
                field.alias or name
                for name, field in cls.model_fields.items()
            ])
            critical = set(value)
            if len(critical) != len(value):
                raise ValueError("The `crit` claim must not contain duplicates.")
            if (critical - known_claims):
                unknown = critical - known_claims
                raise ValueError(
                    f"Header contains critical unknown claims: {str.join(', ', unknown)}"
                )
        return value # pragma: no cover


    @pydantic.field_validator('jku', 'x5u', mode='after', check_fields=False)
    def postprocess_rfc6125(
        cls,
        value: JSONWebKeySetURL | None,
        info: pydantic.ValidationInfo
    ):
        ctx = cast(dict[str, Any], info.context or {})
        if ctx.get('strict', True) and value is not None:
            assert info.field_name
            allowed: set[str] = ctx.get(info.field_name) or set()
            for whitelisted in allowed:
                if isinstance(whitelisted, DomainName)\
                and value.parts.hostname == whitelisted:
                    break
                if isinstance(whitelisted, HTTPResourceLocator)\
                and value.is_subpath(whitelisted):
                    break
            else:
                raise ValueError(f'The "{info.field_name}" claim is not acceptable')

        return value

    @pydantic.field_validator('cty', 'typ', mode='before', check_fields=False)
    def preprocess_media_type(cls, value: str | None):
        # RFC 7515: A recipient using the media type value MUST treat it as
        # if "application/" were prepended to any "typ" value not containing
        # a '/'.  For instance, a "typ" value of "example" SHOULD be used
        # to represent the "application/example" media type, whereas the
        # media type "application/example;part="1/2"" cannot be shortened
        # to "example;part="1/2"".
        if value is not None:
            value = str.lower(value)
        if value is not None and '/' not in value:
            value = f'application/{value}'
        return value

    @pydantic.field_serializer('cty', 'typ', check_fields=False)
    def postprocess_media_type(self, value: str | None):
        if value is not None and value.startswith('application/'):
            value = value.replace('application/', '')
        if value is not None and str.lower(value) in {'jwt'}:
            value = str.upper(value)
        return value

    def keys(self):
        return set(self.model_fields_set)

    def urlencode(self):
        return b64encode(bytes(self)) if self else b''

    def __bytes__(self):
        claims = self.model_dump_json(
            exclude_defaults=True,
            exclude_none=True,
            exclude_unset=True
        )
        return str.encode(claims, 'utf-8')

    def __bool__(self):
        return bool(
            self.model_dump(
                exclude_defaults=True,
                exclude_unset=True,
                exclude_none=True
            )
        )