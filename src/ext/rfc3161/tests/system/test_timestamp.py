import pytest

from aegisx.ext.rfc3161 import TimestampClient


TIMESTAMP_SERVERS = [
    ('http://timestamp.wosign.com/rfc3161', 'sha256'),
    ('http://tsa.swisssign.net', 'sha256'),
    ('http://timestamp.comodoca.com', 'sha256'),
    ('http://timestamp.acs.microsoft.com', 'sha256'),
    ('http://timestamp.entrust.net/TSS/RFC3161sha2TS', 'sha256'),
    #('http://services.globaltrustfinder.com/adss/tsa', 'sha256'),
    ('https://ca.signfiles.com/tsa/get.aspx', 'sha256'),
    ('http://zeitstempel.dfn.de', 'sha256'),
    #('http://dse200.ncipher.com/TSS/HttpTspServer', 'sha256'),
    #('http://tsa.startssl.com/rfc3161', 'sha256'),
    #('https://freetsa.org', 'sha256'),
    ('http://time.certum.pl', 'sha256'),
    #('http://tsa.mesign.com', 'sha256'),
    ('http://timestamp.apple.com/ts01', 'sha256'),
    ('http://timestamp.sectigo.com', 'sha256'),
    ('http://rfc3161timestamp.globalsign.com/advanced', 'sha256'),
    ('http://timestamp.globalsign.com/tsa/r6advanced1', 'sha256'),
    ('http://timestamp.digicert.com', 'sha256'),
    #('http://rfc3161.ai.moda', 'sha256'),
    #('https://rfc3161.ai.moda/any', 'sha256'),
    #('https://rfc3161.ai.moda/apple', 'sha256'),
    #('https://rfc3161.ai.moda/microsoft', 'sha256'),
    #('https://rfc3161.ai.moda/adobe', 'sha256'),
    #('https://rfc3161.ai.moda', 'sha256'),
]


@pytest.mark.parametrize("url,alg", TIMESTAMP_SERVERS)
@pytest.mark.asyncio
async def test_timestamp_responses(url: str, alg: str):
    async with TimestampClient() as client:
        ts = await client.timestamp(url=url, data=b'Hello world!', algorithm=alg) # type: ignore


@pytest.mark.asyncio
async def test_timestamp_multi():
    async with TimestampClient() as client:
        await client.timestamps(data=b'Hello world!')