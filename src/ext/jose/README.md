# Javascript Object Signing and Encryption (JOSE)

**The aegisx.ext.jose module provides a high-level interface for working with
the JSON Object Signing and Encryption (JOSE) family of standards, including
JWS, JWE, JWK, and JWT. Built on top of AegisX’s extensible cryptographic
framework, this module simplifies the secure handling of tokens and key
material across authentication and authorization workflows. It is designed
to be both flexible and standards-compliant, making it easy to integrate
JOSE-based protocols into modern Python applications.**

## Installation

Installation is as simple as running the following command:

```
pip install aegisx.ext.jose
```

## Standards

- RFC 7515 JSON Web Signature (JWS)
- RFC 7516 JSON Web Encryption (JWE)
- RFC 7517 JSON Web Key (JWK)
- RFC 7518 JSON Web Algorithms (JWA)
- RFC 7519 JSON Web Token (JWT)
- RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
- RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)

## TODO:

- RFC 7515 4.1.6: Certificate chain verification for `x5u`/`x5c`.
- RFC 7515 10.13.: Unicode Comparison Security Considerations