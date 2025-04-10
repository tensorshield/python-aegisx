


OID_HASHING_ALGORITHMS = {
    '1.3.14.3.2.26'         : 'sha1',
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
}

TIMESTAMP_SERVERS: list[tuple[str, float]] = [
    ('http://tsa.swisssign.net', 0.75),
    ('http://timestamp.comodoca.com', 0.75),
    ('http://timestamp.acs.microsoft.com', 0.75),
    ('http://timestamp.entrust.net/TSS/RFC3161sha2TS', 0.25),
    ('https://ca.signfiles.com/tsa/get.aspx', 0.25),
    ('http://zeitstempel.dfn.de', 0.25),
    ('http://time.certum.pl', 0.1),
    ('http://tsa.mesign.com', 0.1),
    ('http://timestamp.apple.com/ts01', 0.8),
    ('http://timestamp.sectigo.com', 0.25),
    ('http://rfc3161timestamp.globalsign.com/advanced', 0.25),
    ('http://timestamp.globalsign.com/tsa/r6advanced1', 0.25),
    ('http://timestamp.digicert.com', 0.25),
]