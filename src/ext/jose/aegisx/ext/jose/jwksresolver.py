import asyncio
import json
import logging
import urllib.parse
from typing import Iterable

import httpx
import pydantic

from .models import JSONWebKeySet


class JWKSResolver:
    cache: dict[str, JSONWebKeySet]
    domains: set[str]
    logger: logging.Logger = logging.getLogger(__name__)
    timeout: float = 5.0
    Unresolvable: type[Exception] = type('Unresolvable', (Exception,), {})

    def __init__(
        self,
        *,
        domains: Iterable[str],
        logger: logging.Logger | None = None
    ):
        self.cache = {}
        self.domains = set(domains)
        self.lock = asyncio.Lock()
        self.logger = logger or self.logger

    def is_trusted_source(self, url: str):
        """Return ``True`` if the `url` is trusted to obtain a JWKS
        from.
        """
        p = urllib.parse.urlparse(url)
        return all([
            p.netloc in self.domains,
            p.scheme == 'https'
        ])

    async def resolve(
        self,
        url: str,
        keys: Iterable[str] | None = None,
        fatal: bool = False,
        force: bool = False,
    ) -> JSONWebKeySet:
        """Resolve a JSON Web Key Set (JWKS) from the given `url`. Cache
        the results on succesful response.

        The `keys` parameter is an iterable of strings that indicate
        which keys (identified by the `kid` claim) must be present in
        the JWKS. If any of these identifiers is not present, then
        the cached instance is refreshed.

        The `fatal` parameter indicates if a failure to obtain the JWKS
        from the given `url` should raise an exception. The default is
        ``False``, which causes :meth:`resolve()` to return an empty
        :class:`JSONWebKeySet` instance.

        If the `force` parameter is ``True``, the JWKS is always obtained
        from the given `uri` instead of the local cache.
        """
        keys = set(keys or [])
        if not self.is_trusted_source(url):
            self.logger.critical(
                'Can not obtain JWKS from %s because it is not a trusted '
                'source.',
                url
            )
            return JSONWebKeySet(keys=[])

        async with self.lock:
            if url in self.cache and not force:
                self.logger.debug('Obtained JWKS %s from cache.')
                jwks = self.cache.get(url)
                assert jwks is not None
                if any([k.kid in keys for k in jwks.keys]) or not keys:
                    return jwks

            async with httpx.AsyncClient() as client:
                try:
                    response = await client.get(
                        url=url,
                        follow_redirects=True,
                        timeout=self.timeout
                    )
                    if response.status_code != 200:
                        self.logger.warning(
                            'Server returned non-200 response while obtaining '
                            'JWKS from %s (status: %s)',
                            url,
                            response.status_code
                        )
                        if fatal:
                            raise self.Unresolvable
                        jwks = JSONWebKeySet(keys=[])
                    else:
                        jwks = JSONWebKeySet.model_validate_json(response.text)

                        # Only cache the response if it was succesful.
                        self.cache[url] = jwks
                except (ValueError, TypeError, json.JSONDecodeError, pydantic.ValidationError):
                    self.logger.warning(
                        'Unable to decoded JWKS from %s',
                        url
                    )
                    if fatal:
                        raise self.Unresolvable
                    jwks = JSONWebKeySet(keys=[])
                except httpx.TimeoutException:
                    self.logger.warning(
                        'Caught timeout while obtaining JWKS from %s',
                        url
                    )
                    if fatal:
                        raise self.Unresolvable
                    jwks = JSONWebKeySet(keys=[])
            self.logger.debug('Obtained JWKS %s from remote.')
        return jwks
        