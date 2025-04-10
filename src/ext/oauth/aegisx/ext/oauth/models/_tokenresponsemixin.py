import pydantic


class TokenResponseMixin:

    @pydantic.field_validator('token_type', mode='before')
    @classmethod
    def preprocess_token_type(cls, value: str | None):
        if value is not None:
            value = str.lower(value)
        return value