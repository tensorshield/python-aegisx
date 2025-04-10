import json
import urllib.parse
from typing import cast
from typing import Any

import pydantic

from ._oidcrequestedclaims import RequestedClaims


class OIDCClaimSpec(pydantic.BaseModel):
    userinfo: RequestedClaims | None = pydantic.Field(
        default=None,
        title="UserInfo Endpoint Claims",
        description=(
            "Requests that the listed individual claims be returned from the UserInfo endpoint. "
            "If present, the listed claims are being requested to be added to any claims that "
            "are being requested using scope values. If not present, the claims being requested "
            "from the UserInfo Endpoint are only those requested using scope values."
        )
    )

    id_token: RequestedClaims | None = pydantic.Field(
        default=None,
        title="ID Token Claims",
        description=(
            "Requests that the listed individual claims be returned in the ID Token. If present, "
            "the listed claims are being requested to be added to the default claims in the ID "
            "Token. If not present, the default ID Token claims are requested."
        )
    )

    @pydantic.model_validator(mode='before')
    @classmethod
    def preprocess(
        cls,
        values: dict[str, Any] | str
    ) -> dict[str, Any]:
        if isinstance(values, str):
            values = cast(
                dict[str, Any],
                json.loads(urllib.parse.unquote_plus(values))
            )
        return values

    @pydantic.model_serializer(mode='wrap', when_used='always')
    def serialize(
        self,
        nxt: pydantic.SerializerFunctionWrapHandler,
        info: pydantic.SerializationInfo
    ):
        match info.mode:
            case 'query':
                return urllib.parse.quote_plus(
                    json.dumps(
                        self.model_dump(mode='json'),
                        separators=(',', ':')
                    )
                )
            case _:
                return nxt(self)