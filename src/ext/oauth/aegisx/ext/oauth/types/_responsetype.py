import enum


class ResponseType(str, enum.Enum):
    CODE                = 'code'
    CODE_ID_TOKEN       = 'code id_token'
    CODE_ID_TOKEN_TOKEN = 'code id_token token'
    CODE_TOKEN          = 'code token'
    ID_TOKEN_TOKEN      = 'id_token token'
    ID_TOKEN            = 'id_token'
    TOKEN               = 'token'
    NONE                = 'none'