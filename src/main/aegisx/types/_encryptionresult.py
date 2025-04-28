import pydantic


class EncryptionResult(pydantic.BaseModel):
    ct: bytes
    iv: bytes = b''
    aad: bytes = b''
    tag: bytes = b''