from libcanonical.types import HTTPResourceLocator


class HTTPSResourceLocator(HTTPResourceLocator):
    protocols = {'https'}