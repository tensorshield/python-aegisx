from libcanonical.types import StringType

from ._jsonwebalgorithmconfig import JSONWebAlgorithmConfig


class JSONWebAlgorithm(StringType):
    config: JSONWebAlgorithmConfig

    @classmethod
    def validate(cls, v: str):
        self = cls(v)
        self.config = JSONWebAlgorithmConfig.get(self)
        return self

    @property
    def crv(self):
        return self.config.crv

    @property
    def cipher(self):
        return self.config.cipher

    @property
    def dig(self):
        return self.config.dig

    @property
    def length(self) -> int:
        assert self.config.length, (
            f"JSONWebAlgorithm.length is not available for algorithm "
            f"{self}"
        )
        return self.config.length

    @property
    def mode(self):
        return self.config.mode

    @property
    def use(self):
        return self.config.use

    @property
    def wrap(self):
        if self.config.wrap is not None:
            return JSONWebAlgorithm.validate(self.config.wrap)

    def can_encrypt(self):
        return 'encrypt' in (self.config.key_ops or set())

    def is_direct(self):
        if self.config.mode is None: # pragma: no cover
            return False
        return self.config.mode in {
            'DIRECT_ENCRYPTION',
            'DIRECT_KEY_AGREEMENT',
        }