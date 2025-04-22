from ._resourceserverexception import ResourceServerException


class InvalidRequestToken(ResourceServerException):
    error = 'invalid_token'
    status_code = 403

    def __init__(self, message: str):
        super().__init__(message)