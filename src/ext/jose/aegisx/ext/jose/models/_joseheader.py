import pydantic

from ._jwsheader import JWSHeader


class JOSEHeader(pydantic.RootModel[JWSHeader]):
    pass