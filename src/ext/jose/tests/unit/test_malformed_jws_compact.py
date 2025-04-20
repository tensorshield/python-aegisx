import pytest

from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.types import MalformedEncoding


INVALID_JWS_COMPACT_ENCODING: list[str] = [
    # 1. Incorrect base64url encoding (wrong number of characters)
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwI9',
    
    # 2. Missing '.' separator between segments
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJeyJ1c2VyX2lkIjoxMjM0NTY3ODk',
    
    # 3. Missing header, only payload and signature
    '.eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot',
    
    # 4. Incorrect header format (invalid JSON structure)
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot',
    
    # 5. Invalid base64url in the payload
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjpbIjAsIjE5Il19.',
    
    # 6. Base64 URL encoded segments with padding '=' which is invalid for base64url
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODk9..QdUIwQjSNOxS5nqjjh4OqGb4ehZ6hj9NrHdjgkBCFGo',
    
    # 7. Invalid characters in the header
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC^&%$#@!().JHjw==',
    
    # 8. Empty JWS string
    '',
    
    # 9. Single segment (invalid JWS, needs 3 segments)
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    
    # 10. No base64url encoding (raw JSON object instead of encoded strings)
    '{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe"}.f36f6b01e8bdef28e323e8355cf9bfda9fd02199f90c274ee5e5fdb450745246',
    
    # 11. Header not base64url encoded
    '{invalid_base64}.eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot.',
    
    # 12. Payload has no base64url encoding
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{invalid_base64}.signeddata',
    
    # 13. Signature has no base64url encoding
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot.{invalid_signature_data}',
    
    # 14. Multiple headers, no payload or signature
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.',
    
    # 15. Missing alg in header
    '.eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot.',
    
    # 16. Invalid character in header or payload base64url encoding
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjom!@%^&(){}:.',
    
    # 17. Invalid characters in payload
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjpbIjAsIjE5Il19=',
    
    # 18. Missing JWS type (header missing or malformed)
    '.eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot',
    
    # 20. Extra segments after signature
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot.abcde==extra',
    
    # 21. Payload exceeds 64k length (invalid size for payload)
    #'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + ('A' * 65537) + '.signaturepart',
    
    # 22. Missing payload and signature (empty JWS)
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..',
    
    # 23. Invalid padding in the signature or payload
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODk5OTk5Ojo6Ojot.X8x64==',
    
    # 24. Header with non-standard characters
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjpbIjAsIjE5Il19..@*12345678',
]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", INVALID_JWS_COMPACT_ENCODING)
async def test_malformed_jws_compact_input(value: str):
    with pytest.raises(MalformedEncoding):
        await TokenValidator(bytes, verify=False).validate(value)