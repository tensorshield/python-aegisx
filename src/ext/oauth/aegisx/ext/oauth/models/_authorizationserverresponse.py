import pydantic


class AuthorizationServerResponse(pydantic.BaseModel):
    model_config = {'extra': 'forbid'}

    def is_encrypted(self) -> bool:
        raise NotImplementedError

    def is_signed(self) -> bool:
        raise NotImplementedError

    def is_error(self) -> bool:
        return False