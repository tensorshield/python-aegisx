import time

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import KeySelector


# Test Case 1: Test KeySelector by Algorithm
def test_key_selector_by_algorithm():
    # Generate test keys for signing (use 'sig')
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig'
    )
    key2 = JSONWebKey.generate(
        alg='ES384',
        use='sig'
    )

    # Generate test keys for encryption (use 'enc')
    key3 = JSONWebKey.generate(
        alg='ECDH-ES+A128KW',
        use='enc',
        crv='P-256'
    )
    key4 = JSONWebKey.generate(
        alg='ECDH-ES+A192KW',
        use='enc',
        crv='P-256'
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2, key3, key4])

    # Select keys using algorithm filter (ES256 and ECDH-ES+A128KW)
    selected = selector.select(algorithms=['ES256', 'ECDH-ES+A128KW'])

    # Assert that only the keys with matching algorithms are selected
    assert key1 in selected
    assert key3 in selected
    assert key2 not in selected
    assert key4 not in selected


# Test Case 2: Test KeySelector by Use (sig/enc)
def test_key_selector_by_use():
    # Generate test keys for signing (use 'sig')
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig'
    )
    key2 = JSONWebKey.generate(
        alg='ES384',
        use='sig'
    )

    # Generate test keys for encryption (use 'enc')
    key3 = JSONWebKey.generate(
        alg='ECDH-ES+A128KW',
        use='enc',
        crv='P-256'
    )
    key4 = JSONWebKey.generate(
        alg='ECDH-ES+A192KW',
        use='enc',
        crv='P-256'
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2, key3, key4])

    # Select keys using use filter for signing
    selected_sig = selector.select(use='sig')
    assert key1 in selected_sig
    assert key2 in selected_sig
    assert key3 not in selected_sig
    assert key4 not in selected_sig

    # Select keys using use filter for encryption
    selected_enc = selector.select(use='enc')
    assert key3 in selected_enc
    assert key4 in selected_enc
    assert key1 not in selected_enc
    assert key2 not in selected_enc


# Test Case 3: Test KeySelector by Kid (Key Identifier)
def test_key_selector_by_kid():
    # Generate test keys with specific kid
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        kid='key1'
    )
    key2 = JSONWebKey.generate(
        alg='ES384',
        use='sig',
        kid='key2'
    )

    # Generate test keys for encryption
    key3 = JSONWebKey.generate(
        alg='ECDH-ES+A128KW',
        use='enc',
        kid='key3',
        crv='P-256'
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2, key3])

    # Select keys using kid filter
    selected = selector.select(identifiers=['key1'])
    assert key1 in selected
    assert key3 not in selected
    assert key2 not in selected


# Test Case 4: Test KeySelector with Expiration (exp) and Not Before (nbf) Filtering
def test_key_selector_exp_nbf_filtering():
    # Generate test keys with expiration and not-before claims
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) + 1000,
        nbf=int(time.time()) - 1000
    )
    key2 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) - 1000,
        nbf=int(time.time()) - 1000
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys considering the expiration time
    selected = selector.select(now=int(time.time()) + 500)  # Current time is after the nbf but before the exp
    assert key1 in selected
    assert key2 not in selected


# Test Case 5: Test KeySelector with Multiple Criteria (alg, use, kid)
def test_key_selector_select_multiple_criteria():
    # Generate test keys
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        kid='key1'
    )
    key2 = JSONWebKey.generate(
        alg='ES384',
        use='sig',
        kid='key2'
    )
    key3 = JSONWebKey.generate(
        alg='ECDH-ES+A128KW',
        use='enc',
        kid='key3',
        crv='P-256'
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2, key3])

    # Select keys using multiple criteria
    selected = selector.select(
        identifiers=['key1'],
        algorithms=['ES256'],
        use='sig'
    )
    assert key1 in selected
    assert key3 not in selected
    assert key2 not in selected


# Test Case 6: Test KeySelector with No Matching Keys
def test_key_selector_no_keys_available():
    # Generate test keys
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        kid='key1'
    )
    key2 = JSONWebKey.generate(
        alg='ES384',
        use='sig',
        kid='key2'
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys that don't match any criteria
    selected = selector.select(identifiers=['kid:key3'])
    assert not selected  # No keys should match


# Test Case 7: Test KeySelector with Expired Key
def test_key_selector_expired_key():
    # Generate test key with expired date
    expired_key = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) - 1000
    )

    # Initialize KeySelector with expired key
    selector = KeySelector([expired_key])

    # Select keys considering the expiration time (key is expired)
    selected = selector.select(now=int(time.time()) + 500)
    assert expired_key not in selected


# Test Case 8: Test KeySelector with Maximum Clock Skew
def test_key_selector_with_max_clock_skew():
    # Generate test keys
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) + 1000,
        nbf=int(time.time()) - 1000
    )
    key2 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) - 1000,
        nbf=int(time.time()) - 1000
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys with a maximum clock skew of 1000 seconds
    selected = selector.select(now=int(time.time()) + 500, max_clock_skew=1000)
    assert key1 in selected
    assert key2 not in selected


# Test Case 9: Test KeySelector with Non-Matching Use Case
def test_key_selector_non_matching_use():
    # Generate test keys with different uses
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        kid='key1'
    )
    key2 = JSONWebKey.generate(
        alg='ECDH-ES+A128KW',
        use='enc',
        kid='key2',
        crv='P-256',
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys using "sig" use filter (should only return key1)
    selected = selector.select(use='sig')
    assert key1 in selected
    assert key2 not in selected


# Test Case 10: Test KeySelector Select No Keys After Filtering
def test_key_selector_no_keys_after_filtering():
    # Generate test keys
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        kid='key1'
    )
    key2 = JSONWebKey.generate(
        alg='ES384',
        use='sig',
        kid='key2'
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys using non-matching criteria (e.g., non-existing kid)
    selected = selector.select(identifiers=['kid:key3'])
    assert not selected  # No keys should match


# Test Case 11: Test KeySelector with Expiration (exp) Claim Filtering
def test_key_selector_with_expiration():
    # Generate test keys with expiration claim
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) + 1000  # Expires in the future
    )
    key2 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) - 1000  # Expired
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys considering the expiration time (key1 should be valid)
    selected = selector.select(now=int(time.time()) + 500)  # Current time is after the nbf but before the exp
    assert key1 in selected
    assert key2 not in selected


# Test Case 12: Test KeySelector with Not Before (nbf) Claim Filtering
def test_key_selector_with_not_before():
    # Generate test keys with not-before claim
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        nbf=int(time.time()) - 1000  # Valid from a past time
    )
    key2 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        nbf=int(time.time()) + 1000  # Not valid yet
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys considering the not-before time (key1 should be valid)
    selected = selector.select(now=int(time.time()) + 500)  # Current time is after the nbf for key1
    assert key1 in selected
    assert key2 not in selected


# Test Case 13: Test KeySelector with Expiration and Not Before Claims Combined
def test_key_selector_exp_and_nbf_combined():
    # Generate test keys with both expiration and not-before claims
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) + 1000,  # Expiration in the future
        nbf=int(time.time()) - 1000  # Valid from the past
    )
    key2 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) - 1000,  # Expired
        nbf=int(time.time()) - 1000  # Valid from the past
    )
    key3 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) + 1000,  # Expires in the future
        nbf=int(time.time()) + 1000  # Not valid yet
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2, key3])

    # Select keys considering both expiration and not-before
    selected = selector.select(now=int(time.time()) + 500)  # Current time is valid for key1 only
    assert key1 in selected
    assert key2 not in selected
    assert key3 not in selected


# Test Case 14: Test KeySelector Select No Keys After Filtering (no valid keys)
def test_key_selector_no_valid_keys_after_filtering():
    # Generate test keys
    key1 = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        kid='key1',
        exp=int(time.time()) - 1000  # Expired key
    )
    key2 = JSONWebKey.generate(
        alg='ES384',
        use='sig',
        kid='key2',
        exp=int(time.time()) - 1000  # Expired key
    )

    # Initialize KeySelector with all keys
    selector = KeySelector([key1, key2])

    # Select keys using non-matching criteria (expired keys should be excluded)
    selected = selector.select(now=int(time.time()) + 500)
    assert not selected  # No valid keys should match


# Test Case 15: Test KeySelector with Expired Key and Maximum Clock Skew
def test_key_selector_with_expired_key_and_clock_skew():
    # Generate test key with expired date
    expired_key = JSONWebKey.generate(
        alg='ES256',
        use='sig',
        exp=int(time.time()) - 1000  # Expired key
    )

    # Initialize KeySelector with expired key
    selector = KeySelector([expired_key])

    # Select keys considering the expiration time (expired key should be excluded even with skew)
    selected = selector.select(now=int(time.time()) + 500, max_clock_skew=1000)
    assert expired_key not in selected