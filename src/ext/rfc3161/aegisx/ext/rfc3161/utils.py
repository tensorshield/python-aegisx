from .const import OID_HASHING_ALGORITHMS


def digest_algorithm_name(oid: str):
    try:
        return OID_HASHING_ALGORITHMS[oid]
    except KeyError:
        raise ValueError(f"Unknown digest algorithm: {oid}")