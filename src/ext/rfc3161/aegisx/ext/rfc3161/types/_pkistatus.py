from pyasn1.type.univ import Integer
from pyasn1.type.namedval import NamedValues


class PKIStatus(Integer):
    namedValues = NamedValues(
        ('granted', 0),
        ('grantedWithMods', 1),
        ('rejection', 2),
        ('waiting', 3),
        ('revocationWarning', 4),
        ('revocationNotification', 5)
    )