import sys
from typing import NoReturn


class OpenAuthorizationError(Exception):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    default_description: str | None = None

    def __init__(self, description: str | None = None):
        self.description = description or self.default_description

    def fatal(self) -> NoReturn:
        sys.stderr.write(f'{self.FAIL}{self.description}{self.ENDC}')
        raise SystemExit()


class ServerError(OpenAuthorizationError):
    pass


class MetadataError(ServerError):
    pass



class NotDiscoverable(MetadataError):
    pass


class NeedsDiscovery(MetadataError):
    default_description= (
        "The authorization servers' metadata is not discovered yet. Call "
        "ServerMetadata.discover() before using this instance."
    )


class ClientConfigurationError(OpenAuthorizationError):
    pass


class Error(OpenAuthorizationError):
    pass