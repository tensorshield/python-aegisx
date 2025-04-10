# Identity and Access Management (IAM) for Python Web Applications

**The `aegisx.ext.iam` package provides a comprehensive model to implement
Identity and Access Management (IAM) in your Python applications. It offers
out-of-the-box support for both Role-Based Access Control (RBAC) and
Attribute-Based Access Control (ABAC), allowing you to manage and enforce
fine-grained access policies for users within your system.**

Designed with flexibility in mind, the package seamlessly integrates with
**FastAPI**, making it a perfect choice for modern web applications. However,
it can also be easily adapted to work with other Python web frameworks,
providing broad compatibility across various project setups.

With `aegisx.ext.iam`, you can manage user roles, permissions, and attributes,
and apply advanced access control rules to secure your APIs and resources.
This empowers your system to enforce secure, scalable, and maintainable access
management policies.

## Key Features

- **Role-Based Access Control (RBAC)**: Easily manage and assign roles to users.
- **Attribute-Based Access Control (ABAC)**: Implement advanced access
  policies based on user attributes, resources, and environmental conditions.
- **Policy-Driven**: Define access policies using a flexible IAM model,
  including role and permission bindings.
- **CEL (Common Expression Language) Support**: Support for complex condition
  expressions to enforce policies dynamically.
- **FastAPI Integration**: Seamless integration with FastAPI to protect your APIs.
- **Customizable**: Adapt the library for use in any Python web framework.

## Installation

You can install the package via pip:

```
pip install aegisx.ext.iam
```

## Core Concepts

### AuthorizationContext

The `AuthorizationContext` class holds information about the principal (user
or entity), current time, and remote host. It also includes methods to check
whether the principal is anonymous or authenticated.

### IAMBinding

The `IAMBinding` class associates roles with a list of principals (users,
groups, or other entities). It supports conditions, which are expressions
written in the Common Expression Language (CEL), to enforce dynamic access
control rules based on attributes and context.

### IAMCondition

The `IAMCondition` class defines a condition to be associated with a role
binding. The condition uses CEL expressions to evaluate whether the binding
applies based on the current request context.

### IAMPolicy

The `IAMPolicy` class manages a set of role bindings that associate roles
with principals. It provides methods for determining which roles are granted
to a given context and for evaluating the policy based on principal attributes
and conditions.

### RoleDefinition

The `RoleDefinition` class defines a role, its description, and the permissions
it grants. Roles can inherit permissions from other roles, and the permissions
are represented as a set of `Permission` objects.

### RoleDefinitionRequest

The `RoleDefinitionRequest` class is used to define a role and its associated
permissions when creating or updating a role. It ensures that roles are validated
and permissions are expanded according to the defined context.

### Role

The `Role` class represents a named role within the IAM system. It inherits from
`RoleDefinition` and can be validated and populated based on a `RoleValidationContext`.
It ensures that roles are properly configured with permissions and associated with
the correct context.

## Usage Example

To create a root IAM policy and bind principals to a role:

```python
from aegisx.ext.iam import IAMPolicy

policy = IAMPolicy.root(principals=["user:example@example.com"], role="roles/admin")
```

