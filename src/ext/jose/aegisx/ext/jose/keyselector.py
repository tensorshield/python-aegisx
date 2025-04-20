import collections
import time
from typing import Any
from typing import Iterable
from typing import Literal

from .models import JSONWebKey


class KeySelector:
    _algorithms: dict[str, list[JSONWebKey]]
    _candidates: set[JSONWebKey]
    _index: dict[str, JSONWebKey]

    def __init__(
        self,
        candidates: Iterable[JSONWebKey]
    ):
        self._algorithms = collections.defaultdict(list)
        self._candidates = set()
        self._index = {}
        self.update(candidates)

    def add(self, key: JSONWebKey): # pragma: no cover
        """Add the given key to the available candidates and update the
        indexes.
        """
        self.update([key])

    def select(
        self,
        identifiers: Iterable[str] | None = None,
        thumbprints: Iterable[str] | None = None,
        algorithms: Iterable[str] | None = None,
        keys: Iterable[JSONWebKey] | None = None,
        key: JSONWebKey | None = None,
        kid: str | None = None,
        crv: str | None = None,
        use: Literal['sig', 'enc'] | None = None,
        now: int | None = None,
        max_clock_skew: int  = 0
    ) -> 'KeySelector':
        """Filter the :class:`KeySelector` using the given parameters
        and return a new instance.
        """
        if not self._candidates:
            return KeySelector([])
        algorithms = set(algorithms or [])
        identifiers = {f'kid:{k}' for k in set(identifiers or [])}
        keys = set(keys or [])
        thumbprints = set(thumbprints or [])
        if key is not None:
            keys.add(key)
        if kid is not None:
            identifiers.add(f'kid:{kid}')

        # If key identifiers are specified, only exact matching keys
        # are selected.
        if identifiers or thumbprints or keys:
            selector = KeySelector({
                *set([self._index[k] for k in identifiers if k in self._index]),
                *set([self._index[t] for t in thumbprints if t in self._index]),
                *set([key for key in keys if key.thumbprint('sha256') in self._index])
            })
            return selector.select(
                algorithms=algorithms,
                use=use,
                now=now,
                max_clock_skew=max_clock_skew
            )

        candidates: Iterable[JSONWebKey] = set(self._candidates)
        if algorithms:
            candidates = filter(lambda key: key.alg in {None, *algorithms}, candidates)

        if crv:
            candidates = filter(lambda key: key.crv == crv, candidates)

        # This assumes that a JWK that does not specify the "use"
        # claim may be used for both signing and encryption
        # operations.
        if use:
            candidates = filter(lambda key: key.use == use, candidates)

        # Filter all keys that are not usable at the given date and time.
        now = now or int(time.time())
        candidates = filter(
            lambda key: key.exp is None or (key.exp + max_clock_skew) > now,
            candidates
        )
        candidates = filter(
            lambda key: key.nbf is None or (key.nbf - max_clock_skew) <= now,
            candidates
        )
        return KeySelector(candidates)

    def update(self, keys: Iterable[JSONWebKey]):
        """Add the given `keys` to the available candidates and update the
        internal indexes.
        """
        for key in keys:
            self._index[key.thumbprint('sha256')] = key
            if key.kid is not None:
                self._index[f'kid:{key.kid}'] = key
            if key.alg is not None:
                self._algorithms[key.alg].append(key)
            self._candidates.add(key)

    def __bool__(self):
        return bool(self._candidates)

    def __contains__(self, key: Any):
        if not isinstance(key, JSONWebKey):
            return NotImplemented
        return key in self._candidates

    def __iter__(self):
        return iter(self._candidates)

    def __repr__(self):
        return f'KeySelector(candidates={repr(self._candidates)})'