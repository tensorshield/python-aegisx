import pydantic

from ._accesstokentokenresponse import AccessTokenTokenResponse


class ProofOfPossessionTokenResponse(AccessTokenTokenResponse):
    cnf: str | None = pydantic.Field(
        default=None,
        description=(
            "Present if the token type is `pop` and a symmetric key is "
            "used. MAY be present for asymmetric PoP keys. This field "
            "contains the PoP key that the AS selected for the token. "
            "Values of this parameter follow the syntax and semantics "
            "of the `cnf` claim either from Section 3.1 of RFC 8747 for "
            "CBOR-based interactions or from Section 3.1 of RFC 7800 for "
            "JSON-based interactions."
        )
    )

    rs_cnf: str | None = pydantic.Field(
        default=None,
        description=(
            "Present if the token type is `pop` and asymmetric keys are used. "
            "Not present otherwise. This field contains information about the "
            "public key used by the RS to authenticate. If this parameter is "
            "absent, either the RS does not use a public key or the AS knows "
            "that the RS can authenticate itself to the client without additional "
            "information. Values of this parameter follow the syntax and semantics "
            "of the cnf claim either from Section 3.1 of RFC 8747 for CBOR-based "
            "interactions or from Section 3.1 of RFC 7800 for JSON-based interactions."
        )
    )

    @pydantic.model_validator(mode='after')
    def postprocess(self):
        if not self.cnf and not self.rs_cnf:
            raise ValueError("not a proof-of-possession token response.")
        return self