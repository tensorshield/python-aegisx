# Pinned dependencies for high-security environments

**The aegisx.ext.cve package is designed to enhance the security of
your AegisX environment by providing curated dependency pinning
that excludes known vulnerabilities (CVEs) from the dependency tree.**

**By default, AegisX avoids pinning dependencies across its packages to
maintain backward compatibility and allow implementers to apply their
own security policies. The aegisx.ext.cve package overrides this 
behavior, ensuring that all dependencies are locked to versions free
from known security flaws. This package is particularly recommended
for high-security environments where stricter control over vulnerabilities
is essential.**

## Changelog

### 0.0.1

- **CVE-2024-12797** Pin `cryptography>=0.44.0`
- **CVE-2024-47874** Pin `starlette>=0.40.0` in the `fastapi` extra.