<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to OrionGrant are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-15

### Added

Initial release. Permission and policy authorization.

- `PermissionMatcher`: hierarchical colon-scoped permission matching with wildcard semantics
  (`orders:*`, mid-segment `*`, `*`).
- `IGrantAuthorizer` / `GrantAuthorizer`: expands a principal's roles into permissions, unions
  them with direct grants, and authorizes a single permission or a named policy.
- `RoleRegistry` and `PolicyRegistry`: immutable maps built at registration.
- `AccessPolicy` with `PolicyMode` (RequireAll / RequireAny).
- `GrantPrincipal`: subject plus roles and direct permissions.
- `AuthorizationResult`: granted, or denied with a reason.
- `GrantDiagnostics`: `Moongazing.OrionGrant` meter with an outcome/kind-tagged decision counter.
- `AddOrionGrant()` DI extension with a role/policy builder.

### Tests

24 tests across the matcher (specification table), the authorizer (direct, role expansion,
unknown role, effective set, policy all-of/any-of, unknown policy), and registration.

[0.1.0]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.1.0
