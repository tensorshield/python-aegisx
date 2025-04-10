from typing import cast
from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic


I = TypeVar('I', bound=Any)
T = TypeVar('T')


class ClaimRequest(pydantic.BaseModel, Generic[T]):
    essential: bool = pydantic.Field(
        default=False,
        title="Essential",
        description=(
            "Indicates whether the claim being requested is essential. "
            "If the value is `true`, this indicates that the claim is an "
            "essential claim."
        )
    )

    values: list[T] | None = pydantic.Field(
        default=None,
        title="Values",
        min_length=1,
        description=(
            "Requests that the claim be returned with one of a set of values, "
            "with the values appearing in order of preference. This is "
            "processed equivalently to a value request, except that a choice "
            "of acceptable claim values is provided."
        )
    )

    @pydantic.model_validator(mode='before')
    @classmethod
    def preprocess(cls, value: I) -> I:
        if isinstance(value, dict):
            value = cast(dict[str, Any], value) # type: ignore
            if value.get('value') and value.get('values'):
                raise ValueError(
                    'the "value" and "values" parameters '
                    'are mutually exclusive.'
                )
            if 'value' in value:
                value['values'] = [value.pop('value')]
        return value

    @pydantic.model_serializer(mode='plain', when_used='json')
    def serialize(self) -> None | dict[str, bool | list[T]]:
        adapter: pydantic.TypeAdapter[list[T]] = pydantic.TypeAdapter(ClaimRequest.model_fields['values'].annotation)
        return None if self.is_voluntary() else {
            'essential': self.essential,
            'values': adapter.dump_python(self.values) # type: ignore
        }

    def is_voluntary(self) -> bool:
        return self.values is None and not self.essential