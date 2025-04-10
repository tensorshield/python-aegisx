from aegisx.ext.jose.models import JWEHeader



def test_union_order():
    a = JWEHeader.model_validate({'alg': 'A128GCMKW'})
    b = JWEHeader.model_validate({'alg': 'A256GCMKW'})
    assert (a | b).alg == 'A256GCMKW'