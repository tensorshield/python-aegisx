import enum


class AccessTokenType(str, enum.Enum):
    BEARER  = 'bearer'
    N_A     = 'n_a'
    POP     = 'pop'
    DPOP    = 'dpop'