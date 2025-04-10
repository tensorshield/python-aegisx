import enum


class ClientAuthenticationMethod(str, enum.Enum):
    none                        = 'none'
    client_secret_post          = 'client_secret_post'
    client_secret_basic         = 'client_secret_basic'
    client_secret_jwt           = 'client_secret_jwt'
    private_key_jwt             = 'private_key_jwt'
    tls_client_auth             = 'tls_client_auth'
    self_signed_tls_client_auth = 'self_signed_tls_client_auth'