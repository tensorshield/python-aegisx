from ._joseexception import JOSEException


class InvalidSignature(JOSEException):
    pass


class NotVerifiable(InvalidSignature):
    pass