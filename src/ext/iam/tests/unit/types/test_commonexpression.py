import json

import pydantic
import pytest

from aegisx.ext.iam.types import CommonExpression

# All valid CEL expressions (syntactically correct)
VALID_INPUTS: list[str] = [
    # Comparison
    'a == b',
    'x != y',
    'a < b',
    'a <= b',
    'a > b',
    'a >= b',
    
    # Arithmetic
    '1 + 2',
    'a - b',
    'a * b',
    'x / y',
    'n % m',
    
    # Logical
    'true && false',
    'x || y',
    '!a',
    '!(x && y)',
    'a && !b',
    
    # Ternary
    'a ? b : c',
    'x > y ? "yes" : "no"',
    'true ? 1 : 0',
    
    # Grouping
    '(a + b)',
    '(x > y) && (y < z)',
    '((a))',
    
    # Literals
    '"string"',
    '123',
    'true',
    'false',
    'null',
    
    # Field access
    'a.b',
    'user.profile.name',
    'x.y.z.w',
    
    # Indexing
    'arr[0]',
    'map["key"]',
    'nested["a"]["b"]',
    
    # Function calls
    'size(arr)',
    'has(user.name)',
    'matches(email, ".*@.*")',
    
    # Mixed
    '(a + b) * (c - d)',
    '!(a == b)',
    'x == y && y == z',
    '!(x == 1 || y == 2)',
    'x == 1 ? "a" : "b"',
    
    # Nested ternary
    'x == 1 ? (y == 2 ? "a" : "b") : "c"',
    
    # Collections
    '[1, 2, 3]',
    '{"key": "value"}',
    '[true, false, null]',
    
    # String operations
    '"abc".startsWith("a")',
    '"abc".endsWith("c")',
    '"abc".size()',
    
    # Chained access
    'obj.attr.method()',
    'x.y().z',
    'a.b[0].c',
    
    # Variables
    'user == requester',
    'ip == "127.0.0.1"',
    'time < now',
    
    # Booleans with numbers
    'x > 1 && x < 10',
    '!(x == 1 && y == 2)',
    'x != null',
    
    # Nested expressions
    '(a + (b * c))',
    '!(has(user.email))',
    'a.b.c.d == x',
    
    # Multiple comparisons
    'a == b && b == c && c == d',
    
    # Escaped strings
    '"a\\nb\\tc"',
    '"\\"quoted\\""',
    
    # Unary negatives
    '-1',
    'x + -y',
    '-(a + b)',
    'x * -1',
    
    # Lists & maps
    '{"a": [1, 2, 3]}',
    '[{"x":1}, {"y":2}]',
    '{"key": obj.value}',
    
    # Combinations
    '(x && y) || (a > b)',
    '(a ? b : c) == d',
    '!(x ? y : z)',
]

# Invalid CEL expressions (parsing errors only)
INVALID_INPUTS: list[str] = [
    # Missing operator
    'a b',
    'a ==',
    '== b',
    
    # Invalid comparison
    'a == == b',
    'a == (b + c',
    #'x < y && b && c',
    
    # Logical syntax errors
    'true &&',
    '&& true',
    '!(a || )',
    '!a &&',
    
    # Missing ternary parts
    'a ? : b',
    'a ? b :',
    '? a : b',
    
    # Unbalanced parentheses
    '(a + b',
    'a + (b * c',
    #'((a))',
    
    # Incorrect literal formats
    'true false',
    '123 123',
    'null null',
    
    # Invalid field access
    'a..b',
    'user..name',
    'a["key]',
    
    # Invalid indexing
    'arr[',
    'map["key]',
    #'nested["a"]',
    
    # Incorrect function calls
    #'size()',
    #'has()',
    #'matches()',
    
    # Invalid mixed expressions
    'a + (b * c',
    'a ? b :',
    #'a == b && c == d',
    
    # Nested ternary errors
    'x == 1 ? (y == 2 ? "a" : "b"',
    
    # Invalid collections
    '[1, 2,]',
    #'{key: value}',
    '[true false]',
    
    # Invalid string methods
    #'"abc".startsWith',
    '"abc".endsWith("c"',
    #'"abc".size',
    
    # Invalid chained access
    'obj.attr.',
    'x.y()z',
    #'a.b[0]',
    
    # Invalid variable references
    'user = requester',
    'ip == 127.0.0.1',
    'time < now)',
    
    # Mixed boolean errors
    'x > 1 && < 10',
    '!(x == 1 y == 2)',
    'x !=',
    
    # Invalid nested expressions
    #'a + b (c * d)',
    '!(has(user.email',
    
    # Incorrect comparisons
    'a == == b',
    'x != && y',
    
    # Incorrect escaped strings
    #'"a\\nb"',
    '"\\ "quoted"',
    
    # Invalid unary operations
    '-(a + b',
    #'x * -1',
    'x + y -',
    
    # Invalid lists & maps
    '[1, , 3]',
    '{key: value,}',
    '[1,, 2]',
    
    # Invalid combinations
    'x && y ||',
    '(a == b) ||',
    '(x && y) &&',
]

@pytest.mark.parametrize("value", VALID_INPUTS)
def test_validate_python(value: str):
    adapter: pydantic.TypeAdapter[CommonExpression] = pydantic.TypeAdapter(CommonExpression)
    adapter.validate_python(value)

@pytest.mark.parametrize("value", INVALID_INPUTS)
def test_validate_python_invalid(value: str):
    adapter: pydantic.TypeAdapter[CommonExpression] = pydantic.TypeAdapter(CommonExpression)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(value)

@pytest.mark.parametrize("value", VALID_INPUTS)
def test_validate_json(value: str):
    adapter: pydantic.TypeAdapter[CommonExpression] = pydantic.TypeAdapter(CommonExpression)
    adapter.validate_json(json.dumps(value), strict=True)

@pytest.mark.parametrize("value", VALID_INPUTS)
def test_dump_python(value: str):
    adapter: pydantic.TypeAdapter[CommonExpression] = pydantic.TypeAdapter(CommonExpression)
    p1 = adapter.validate_python(value)
    assert adapter.validate_python(adapter.dump_python(p1)) == p1

@pytest.mark.parametrize("value", VALID_INPUTS)
def test_dump_json(value: str):
    adapter: pydantic.TypeAdapter[CommonExpression] = pydantic.TypeAdapter(CommonExpression)
    p1 = adapter.validate_python(value)
    assert adapter.validate_json(adapter.dump_json(p1)) == p1

def test_json_schema():
    Model = type('Model', (pydantic.BaseModel,), {
        '__annotations__': {'permission': CommonExpression}
    })
    schema = Model.model_json_schema()
    assert 'permission' in schema['properties']