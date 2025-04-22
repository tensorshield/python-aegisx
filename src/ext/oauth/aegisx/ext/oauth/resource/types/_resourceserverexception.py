import secrets

import fastapi


class ResourceServerException(Exception):
    error: str
    status_code: int

    @staticmethod
    def escape(value: str):
        return value.replace('\\', '\\\\').replace('"', '\\"')

    def __init__(self, message: str, /):
        self.message = message

    def get_www_authenticate_header(self) -> str:
        return f'Bearer, error="{self.error}", error_description: "{self.escape(self.message)}"'

    def http(self):
        header = self.get_www_authenticate_header()
        header = f'{header}, nonce="{secrets.token_urlsafe(32)}"'
        raise fastapi.HTTPException(
            status_code=self.status_code,
            detail=self.message,
            headers={'WWW-Authenticate': header}
        )