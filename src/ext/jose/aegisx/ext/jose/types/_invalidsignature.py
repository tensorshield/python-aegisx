from ._joseexception import JOSEException


class SignatureException(JOSEException):
    pass


class InvalidSignature(SignatureException):
    pass


class NotVerifiable(SignatureException):
    pass