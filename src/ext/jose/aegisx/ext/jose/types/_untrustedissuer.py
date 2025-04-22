from ._joseexception import JOSEException


class UntrustedIssuer(JOSEException):
    message: str