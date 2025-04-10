import pathlib


AEGIS_USER_DIR: pathlib.Path = pathlib.Path("~/.aegisx").expanduser()

AEGIS_KEYDIR = AEGIS_USER_DIR.joinpath('keys')

AEGIS_CONFIG_FILE: pathlib.Path = AEGIS_USER_DIR.joinpath('settings.json')

AEGISX_LIBDIR: pathlib.Path = AEGIS_USER_DIR.joinpath('lib')

JOSE_HEADER_PARAMS: set[str] = {
    'alg',
    'jku',
    'jwk',
    'kid',
    'x5u',
    'x5c',
    'x5t',
    'x5t',
    'typ',
    'cty',
    'crit',
    'alg',
    'enc',
    'zip',
    'jku',
    'jwk',
    'kid',
    'x5u',
    'x5c',
    'x5t',
    'x5t#S256',
    'typ',
    'cty',
    'crit',
    'epk',
    'apu',
    'apv',
    'iv',
    'tag',
    'p2s',
    'p2c',
    'iss',
    'sub',
    'aud',
    'b64',
    'ppt',
    'url',
    'nonce',
    'svt',
    'trust_chain',
    'iheSSId',
}