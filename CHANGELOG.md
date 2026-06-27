<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to OrionGrant are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-06-27

### Added

Three composable additions to the authorization model. Everything here is additive and
behavior-compatible: a principal with no denies and a policy with no condition behave exactly as in
0.3.0, and `EffectivePermissions` returns the same allow set as before.

- **Explicit denies (deny-overrides).** `GrantPrincipal` gains a `Denies` collection of permission
  patterns. A deny that covers a required permission overrides any allow that also covers it, so a
  carve-out wins over a grant with documented deny-overrides precedence. Denies use the same wildcard
  matching as grants (`orders:*` denies every `orders:` permission) and apply uniformly across the
  single-permission, resource (object-level), and policy paths, including the resource path's
  ownership and root-wildcard elevation bypass: a deny removes the permission before ownership is
  even considered. A deny-driven denial carries the new `DenialKind.ExplicitDeny` with the required
  permission and the `DenyPattern` that blocked it on `DenialReason`.
- **Attribute-based conditions (ABAC).** A policy may carry an optional `GrantCondition` predicate,
  added via `OrionGrantBuilder.AddPolicy(name, mode, condition, permissions)`. The condition is an
  additional AND gate evaluated after the permission requirement passes, against an
  `AuthorizationAttributes` context (the principal, an optional `ResourceContext`, and a free-form
  environment attribute bag). New `AuthorizePolicy(principal, policyName, attributes)` and
  `AuthorizeAllPolicies(principal, policyNames, attributes)` overloads supply the attributes; the
  existing two-argument overloads synthesize a principal-only context, so a condition that reads only
  the principal still works without them. A failed condition reports `DenialKind.ConditionUnmet` with
  the policy name. Policies with no condition ignore supplied attributes entirely. Both overloads are
  default interface methods, so existing `IGrantAuthorizer` implementors keep compiling.
- **Per-principal effective-set caching.** Opt-in via `OrionGrantBuilder.UseEffectiveSetCache(capacity)`
  (or by passing an `IEffectiveGrantCache` to the new `GrantAuthorizer` constructor). The authorizer
  caches each principal's resolved `EffectiveGrantSet` (its allow union after role and inclusion
  expansion, plus its explicit denies), so a call site that authorizes the same principal many times
  in one request does not re-expand the set per check. The cache is keyed on the principal's role,
  permission, and deny membership, not its subject: a principal whose membership changes computes a
  different key and never serves a stale decision, so a changed role set is a different key rather
  than a cache invalidation. The default `BoundedEffectiveGrantCache` is a thread-safe, bounded LRU
  that caps memory by evicting the least recently used entry on overflow. Without the opt-in the
  authorizer re-expands per check exactly as in 0.3.0. The cache is registered as a singleton only
  when requested.

### Tests

49 new tests per target framework (net8.0, net9.0, net10.0): deny-overrides across the permission,
resource, and policy paths with the structured `ExplicitDeny` cause and the blocking pattern; ABAC
conditions allowing and denying on principal / resource / environment attributes and composing with
require-all, require-any, and denies; the cached authorizer returning the same decision as the
uncached one for every input, not serving a stale decision when a subject's role or deny membership
changes, order-independent keying, and bounded LRU eviction that still answers correctly after
eviction; and batch checks honoring denies and conditions per item, each matching the equivalent
single check.

### Still planned

- **ASP.NET Core integration.** An `AuthorizationHandler` / policy provider that bridges OrionGrant
  to the framework's `[Authorize]` pipeline, plus result helpers that turn a denied
  `AuthorizationResult` into a `ForbidResult` or an RFC 9457 ProblemDetails payload. Deferred to a
  separate companion package so the core stays framework-free; not part of this release.

## [0.3.0] - 2026-06-22

### Added

Three composable additions to the authorization model. The existing permission, policy, and
resource APIs keep their behavior; everything here is additive and non-breaking.

- **Role-to-role inclusion.** `OrionGrantBuilder.IncludeRole(role, params includedRoles)` lets a
  role compose other roles so common bundles stack. Inclusion is transitive (if `editor` includes
  `reader` and `admin` includes `editor`, then `admin` grants `reader`'s permissions) and is
  resolved into each role's effective permission set once at `BuildRoles()` time, so the
  authorization hot path stays a single set lookup with no graph walk. Cycles (a role that includes
  itself directly or transitively) are rejected at registration with the new
  `RoleInclusionCycleException`, whose `Cycle` lists the roles forming the loop, so a
  misconfiguration fails fast at startup instead of looping during a request. `RoleRegistry` gains
  an `IncludedRolesFor(role)` introspection member and a second constructor that accepts the
  declared inclusion edges; the original `RoleRegistry(IReadOnlyDictionary<...>)` constructor is
  unchanged and still does no flattening.
- **Structured denial reasons.** `AuthorizationResult` gains a `DenialReason? Denial` alongside the
  existing `FailureReason` string, so callers can branch on the cause of a denial instead of parsing
  prose. `DenialReason` carries a `DenialKind` (`MissingPermission`, `PolicyNotFound`,
  `PolicyRequirementUnmet`, `ResourceOwnership`) plus the relevant identifiers: the missing
  permission, the policy name and `PolicyMode`, and the resource type/id for an ownership denial.
  The human-readable string is preserved unchanged on every denial path. A new
  `AuthorizationResult.Denied(string, DenialReason)` overload supplies the structured cause; the
  original `Denied(string)` overload stays and produces a null `Denial`.
- **Batch checks.** `IGrantAuthorizer.AuthorizeAll(principal, permissions)` and
  `AuthorizeAllPolicies(principal, policyNames)` evaluate several requirements for one principal in a
  single call, returning one `BatchAuthorizationResult` per requirement in input order. The concrete
  `GrantAuthorizer` expands the principal's effective set once for the whole batch rather than once
  per requirement, so a call site checking many requirements does not pay for that expansion
  repeatedly. Both are default interface methods (delegating per-item to the single-check methods),
  so existing `IGrantAuthorizer` implementors keep compiling. Each item records one decision on the
  `oriongrant.decisions` counter, so a batch of N matches N single calls.

### Tests

49 new tests per target framework (net8.0, net9.0, net10.0) covering transitive role resolution and
diamond inclusion, cycle detection (self, two-role, longer, and self-on-acyclic) terminating with a
clear `RoleInclusionCycleException` rather than looping, a structured denial cause for each denial
kind across the permission / policy / resource paths (including through the interface default
method), and batch checks returning correct per-item results that match the equivalent single-check
semantics, in input order, with one recorded decision per item.

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

[0.4.0]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.4.0
[0.3.0]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.3.0
[0.2.1]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.2.1
[0.2.0]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.2.0
[0.1.0]: https://github.com/tunahanaliozturk/OrionGrant/releases/tag/v0.1.0
