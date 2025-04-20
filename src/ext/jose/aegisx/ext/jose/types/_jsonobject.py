import json
from typing import cast
from typing import Any

from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler

from ._malformed import MalformedEncoding


class JSONObject(dict[str, Any]):

    @classmethod
    def validate(cls, v: str):
        try:
            if not v.startswith('{') or not v.endswith('}'):
                raise MalformedEncoding("Invalid JWS JSON Encoding.")
            data = json.loads(v)
            if not isinstance(data, dict):
                raise MalformedEncoding("Invalid JWS JSON Encoding.")
            return cls(cast(dict[str, Any], data))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise MalformedEncoding("Invalid JWS JSON Encoding.")

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=cls.__default_schema__(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(cls),
                core_schema.chain_schema([
                    core_schema.str_schema(),
                    core_schema.no_info_plain_validator_function(cls.validate),
                ]),
                core_schema.chain_schema([
                    core_schema.is_instance_schema(dict),
                    core_schema.no_info_plain_validator_function(cls),
                ])
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(json.dumps)
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _: CoreSchema,
        handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        schema = handler(cls.__default_schema__())
        schema['title'] = "JSON Object"
        return schema

    @classmethod
    def __default_schema__(cls):
        return core_schema.dict_schema(
            keys_schema=core_schema.str_schema()
        )

    def __repr__(self):
        return f'<{type(self).__name__}: {repr(dict(self))}>'