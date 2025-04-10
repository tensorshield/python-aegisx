

#: The set of standard claims included in an ID Token per
#: OpenID Connect Core 1.0.
OICD_STANDARD_CLAIMS: set[str] = {
    'iss', 'sub', 'aud', 'exp', 'iat'
}

OIDC_AUTHORIZATION_CODE_FLOW_CLAIMS: set[str] = {'at_hash'}

OIDC_IMPLICIT_FLOW_CLAIMS: set[str] = {'at_hash', 'nonce'}

OIDC_HYBRID_FLOW_CLAIMS: set[str] = {'at_hash', 'c_hash', 'nonce'}