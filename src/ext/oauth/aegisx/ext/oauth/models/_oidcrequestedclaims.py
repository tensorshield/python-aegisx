from typing import Any

import pydantic

from ._oidcclaimrequest import ClaimRequest


class RequestedClaims(pydantic.BaseModel):
    model_config = {'extra': 'allow'}
    __pydantic_extra__: dict[str, ClaimRequest[int | str]] = pydantic.Field( # type: ignore
        init=False
    )

    @pydantic.model_validator(mode='before')
    def preprocess(cls, values: dict[str, Any]) -> dict[str, Any]:
        for key, value in values.items():
            if value is not None:
                continue
            values[key] = ClaimRequest(essential=False)
        return values

    def requested(self) -> set[str]:
        """Return the set of claims that are requested."""
        return set(self.__pydantic_extra__.keys())