from ._joseexception import JOSEException


class Malformed(JOSEException):
    """Base class for all exceptions that indicate malformed encoding,
    syntax or schema.
    """
    pass


class MalformedEncoding(Malformed):
    """Raised when a JOSE object could not be decoded from compact,
    flattened or general serialization.
    """
    pass


class MalformedObject(Malformed):
    """Raised when a JOSE object could be decoded, but either the
    object could not be serialized, or the schema did not validate.
    """
    pass


class MalformedHeader(Malformed):
    """Raised when the header of a JOSE object is malformed."""
    pass


class MalformedPayload(Malformed):
    """Raised when the payload of a JOSE object is malformed."""
    pass