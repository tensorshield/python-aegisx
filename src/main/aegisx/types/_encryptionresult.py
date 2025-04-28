import pydantic


class EncryptionResult(pydantic.BaseModel):
    ct: bytes
    iv: bytes | None = None
    aad: bytes | None = None
    tag: bytes | None = None