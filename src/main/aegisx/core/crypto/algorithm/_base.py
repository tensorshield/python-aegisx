from typing import Literal

import pydantic


class BaseAlgorithm(pydantic.BaseModel):
    use: Literal['sig', 'enc']