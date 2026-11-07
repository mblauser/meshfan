# Security policy

meshfan holds a private key. Security bugs are taken seriously.

## Reporting a vulnerability

Do not open a public issue for a security problem. Send it to the
maintainer (see the repository's contact information) with:

- a short description of the problem and where it is,
- the smallest reproduction you can share (secrets removed),
- what you believe the impact is.

A response will come within a reasonable time, and a fix will be
released with a credit unless you ask not to be named.

## What is in scope

- key or secret exposure (logs, `repr()`, files, argv, core dumps),
- TLS misconfiguration that silently disables verification,
- config validation gaps that let a bad or hostile config through,
- anything that lets an untrusted input (topic, broker response)
  forge a log line or crash the relay.

## What is out of scope

- issues that require physical access to the host,
- issues in the dependencies (report them upstream; meshfan pins
  `ed25519-orlp` to 0.1.x),
- the accepted, documented limits in [docs/SECURITY.md](docs/SECURITY.md).

## Disclosure

A confirmed vulnerability is fixed, released, and noted in
[CHANGELOG.md](CHANGELOG.md) before it is discussed publicly.
