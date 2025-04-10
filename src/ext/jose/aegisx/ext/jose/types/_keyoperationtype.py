from typing import Literal


KeyOperationType = Literal[
    'sign',
    'verify',
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
    'deriveKey',
    'deriveBits'
]