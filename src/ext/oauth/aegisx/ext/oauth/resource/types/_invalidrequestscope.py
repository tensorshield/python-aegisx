from ._resourceserverexception import ResourceServerException


class InvalidRequestScope(ResourceServerException):
    error = 'insufficient_scope'
    status_code = 403

    def __init__(self, scope: set[str], message: str | None = None):
        super().__init__(
            'The request requires higher privileges than granted '
            'by the access token.'
        )
        self.scope = scope

    def get_www_authenticate_header(self) -> str:
        header = super().get_www_authenticate_header()
        return f'{header}, scope="{" ".join(sorted(map(self.escape, self.scope)))}"'