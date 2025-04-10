from typing import Any
from typing import Self

from celpy import Environment # type: ignore
from celpy import CELParseError # type: ignore
from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler


class CommonExpression(str):
    """A class that represents a Common Expression Language (CEL) expression.

    This class encapsulates a CEL-based logic expression used in IAM policies
    or conditions. The expression can contain one or more statements, each
    evaluating an attribute. The statements are combined using logical operators
    in accordance with the CEL language specification.
    """
    max_length: int = 512

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=cls.__default_schema__(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(cls),
                cls.__default_schema__(),
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(str)
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _: CoreSchema,
        handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        schema = handler(cls.__default_schema__())
        schema['title'] = "Common Expression Language (CEL)"
        schema['description'] = (
            "Defines an attribute-based logic expression using a subset of the "
            "Common Expression Language (CEL). The condition expression can "
            "contain multiple statements; each statement evaluates one attribute. "
            "Statements are combined using logical operators, following the CEL "
            "language specification."
        )
        return schema

    @classmethod
    def __default_schema__(cls):
        return core_schema.chain_schema([
            core_schema.str_schema(
                max_length=cls.max_length,
                strip_whitespace=True,
            ),
            core_schema.no_info_plain_validator_function(cls.validate)
        ])

    @classmethod
    def validate(cls, value: str) -> Self:
        """Validates the CEL expression.

        This method validates whether the given expression can be parsed by the
        Common Expression Language (CEL) parser. If the expression is invalid,
        a :exc:`ValueError` is raised.

        Args:
            value (str): The CEL expression to validate.

        Returns:
            CommonExpression

        Raises:
            ValueError: If the expression is not a valid CEL expression.
        """
        env = Environment()
        try:
            env.compile(value) 
        except CELParseError:
            raise ValueError("invalid expression.")
        return cls(value)

    def __repr__(self):
        return f'<{type(self).__name__}: {str(self)}'