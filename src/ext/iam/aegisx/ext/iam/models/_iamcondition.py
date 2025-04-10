import pydantic
from libcanonical.types import DigestSHA256

from aegisx.ext.iam.types import CommonExpression


class IAMCondition(pydantic.BaseModel):
    """Represents a condition for IAM bindings, based on Common
    Expression Language (CEL).

    This model defines a condition that can be associated with IAM role bindings.
    The condition contains a title, description, and a CEL-based expression that 
    determines when a role binding is applicable to a principal. The expression 
    allows for attribute-based logic and is evaluated at runtime.

    Attributes:
        title (str): A human-readable title for the condition.
        description (str | None): A detailed description of the condition.
        expression (CommonExpression): A CEL expression that determines the 
            condition logic. It can evaluate attributes and combine them using 
            logical operators.
    """
    title: str = pydantic.Field(
        default=...,
        title="Title",
        max_length=31,
        frozen=True
    )

    description: str | None = pydantic.Field(
        default=...,
        title="Description",
        max_length=255,
        frozen=True
    )

    expression: CommonExpression = pydantic.Field(
        default=...,
        title="Expression",
        description=(
            "Defines an attribute-based logic expression using a subset of the "
            "Common Expression Language (CEL). The condition expression can "
            "contain multiple statements; each statement evaluates one attribute. "
            "Statements are combined using logical operators, following the CEL "
            "language specification."
        ),
        max_length=255,
        frozen=True
    )

    digest: DigestSHA256 = pydantic.Field(
        default_factory=DigestSHA256
    )

    @pydantic.model_validator(mode='after')
    def compute_digest(self):
        h = DigestSHA256.hasher()
        h.update(str.encode(self.title, 'utf-8'))
        if self.description:
            h.update(str.encode(self.description, 'utf-8'))
        h.update(str.encode(self.expression, 'utf-8'))
        return self