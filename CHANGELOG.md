<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to OrionGrant are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-06-20

### Performance

- `PermissionMatcher.IsGranted` no longer splits the pattern and required permission into segment
  arrays on every check. It walks the colon-separated segments of both strings as
  `ReadOnlySpan<char>`, slicing in place and comparing each segment with ordinal equality. The
  matching semantics are identical (every existing test passes unchanged); the difference is purely
  in allocation and throughput. Because `IsGranted` runs once per granted pattern on every
  `Authorize` / policy / resource decision, this removes the two array allocations that previously
  occurred per pattern on the authorization hot path. A representative `IsGrantedByAny` over an
  eight-entry effective set drops from roughly 2,250 ns and 2,232 B to roughly 335 ns and 32 B (the
  remaining allocation is the enumerator over the granted set, not the matcher).

## [0.2.0] - 2026-06-19

### Added

Resource / ownership-aware (object-level) authorization. The existing permission and policy APIs
are unchanged; this is an additive, non-breaking path.

- `Authorize(GrantPrincipal, string, ResourceContext, ResourceAuthorizationOptions?)` on
  `IGrantAuthorizer` (and `GrantAuthorizer`): authorizes a principal for a permission against a
  specific resource. The principal must hold the permission AND either own the resource or hold an
  elevated grant. This is the IDOR fix: holding `accounts:read` is necessary but not sufficient to
  read an account you do not own. Added as a default interface method, so existing `IGrantAuthorizer`
  implementors keep compiling.
- `ResourceContext`: the resource under decision, carrying the owner identity (compared to the
  principal subject) plus optional resource type/id for diagnostics. `ResourceContext.OwnedBy(...)`
  convenience factory.
- `ResourceAuthorizationOptions`: owner comparison (`StringComparison`, ordinal by default) and the
  "owner OR elevated" bypass set (`ElevatedPermissions`, plus `TreatRootWildcardAsElevated` so an
  admin `*` grant bypasses ownership with no per-call configuration).

### Changed

- `GrantDiagnostics` supports optional instance scoping via a new `GrantDiagnostics(string?)`
  constructor and `InstanceTag` property. When set, every measurement carries an `instance` tag so a
  `MeterListener` that filters by meter name (rather than instrument instance) can disambiguate
  multiple coexisting instances instead of double-counting. The parameterless constructor and the
  DI registration are unchanged.
- Resource-aware decisions are recorded on the `oriongrant.decisions` counter with `kind=resource`.

### Tests

183 tests per target framework (net8.0, net9.0, net10.0), adding resource-aware coverage (owner
allowed, non-owner denied despite holding the permission, root/elevated bypass, missing permission
denied regardless of ownership, owner comparison, unowned resource, interface default method) and
`GrantDiagnostics` instance-scoping tests in a non-parallel collection filtered by instrument
instance.

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

[0.2.1]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.2.1
[0.2.0]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.2.0
[0.1.0]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.1.0
