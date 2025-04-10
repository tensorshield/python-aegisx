import enum


class TimestampAuthority(str, enum.Enum):
    APPLE       = 'http://timestamp.apple.com/ts01'
    COMODOCA    = 'http://timestamp.comodoca.com'
    MICROSOFT   = 'http://timestamp.acs.microsoft.com'
    SWISSSIGN   = 'http://tsa.swisssign.net'
    ZEITSTEMPEL = 'http://zeitstempel.dfn.de'