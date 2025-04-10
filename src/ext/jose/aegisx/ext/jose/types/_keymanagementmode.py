from typing import Literal


KeyManagementMode = Literal[
    'KEY_ENCRYPTION',
    'KEY_WRAPPING',
    'DIRECT_ENCRYPTION',
    'DIRECT_KEY_AGREEMENT',
    'KEY_AGREEMENT_WITH_KEY_WRAPPING'
]