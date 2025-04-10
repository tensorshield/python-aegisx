from cryptography.hazmat.primitives.asymmetric import utils
from libcanonical.utils.encoding import number_to_bytes


def normalize_ec_signature(l: int, sig: bytes) -> bytes: # pragma: no cover
    r, s = utils.decode_dss_signature(sig)
    return number_to_bytes(r, l) + number_to_bytes(s, l)
