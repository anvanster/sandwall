# Security policy

sandwall is a security boundary, so reports of ways around it are especially welcome: traffic that leaves a sandbox without being allowed, DNS that reaches a resolver for a name that is not allowlisted, a sandbox reaching the host, cloud metadata or another sandbox, or anything that weakens the guarantees listed under "Threat model" in the [README](README.md).

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/anvanster/sandwall/security/advisories/new), not in public issues.
Include the sandwall version or commit, the kernel and distribution, the policy and daemon flags involved, and the steps or script that reproduce the problem.

You should get a first response within a week.
Once a fix is ready, the advisory is published together with the release that contains it, crediting the reporter unless they prefer otherwise.

## Scope

The behaviors listed under "Known gaps" in the README, such as domain fronting through an allowlisted SNI, are known limitations rather than vulnerabilities.
A new way to exploit one of them more broadly than described there is still worth reporting.

Only the latest commit on `main` is supported while sandwall is in its early releases.
