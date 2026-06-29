# OrionGrant Roadmap

Where OrionGrant is, what has shipped, and what is likely next.

OrionGrant is at `0.5.0`: a dependency-light permission and policy authorization library for .NET, with
hierarchical wildcard permissions, roles (including role-to-role composition), named all-of / any-of
policies, resource / ownership-aware (object-level) checks, explicit denies (deny-overrides),
attribute-based (ABAC) policy conditions, an opt-in per-principal effective-set cache, structured
denial reasons, and batch checks, plus an ASP.NET Core companion package that bridges all of this to
the framework's `[Authorize]` pipeline.
The core model is stable in shape. The forward plan below lists what is likely next,
grouped by milestone. Milestones are direction, not contracts: items move forward when real workloads ask
for them. If something here matters to you, open an issue and say so, that is what moves an item up the list.

---

## Guiding principles

These constrain what is worth adding:

- **Stay dependency-light.** The library depends only on
  `Microsoft.Extensions.DependencyInjection.Abstractions`. Anything that would pull in a heavier
  dependency belongs in a separate companion package, not the core.
- **Keep the hot path pure and synchronous.** The matcher and authorizer are allocation-light and
  trivially testable. New features should not compromise that for the common case.
- **Prefer indirection over special cases.** Named policies already let endpoints stay stable while
  requirements change; new capabilities should follow that grain.

---

## Recently shipped

What was on this list and has since landed. See [CHANGELOG.md](../CHANGELOG.md) for the full notes.

- **Resource / ownership-aware authorization** (`0.2.0`). Object-level checks via the
  `Authorize(principal, permission, ResourceContext, options?)` overload: the principal must hold the
  permission AND either own the resource (`ResourceContext.OwnedBy`) or hold a configured elevated grant
  (`ResourceAuthorizationOptions.ElevatedPermissions`, with a root `*` bypass on by default). This closes
  the IDOR gap, where holding `accounts:read` is necessary but not sufficient to read an account the
  principal does not own. Added as a default interface method, so existing implementors keep compiling.
  Resource decisions are tagged `kind=resource` on the `oriongrant.decisions` counter.
- **Allocation-free permission matching** (`0.2.1`). `PermissionMatcher.IsGranted` now walks the
  colon-separated segments of both strings as `ReadOnlySpan<char>` and compares them ordinally in place,
  rather than splitting each into segment arrays per check. Matching semantics are unchanged; the two
  per-pattern array allocations on the authorization hot path are gone.
- **Role-to-role inclusion** (`0.3.0`). `OrionGrantBuilder.IncludeRole` lets a role compose other
  roles; permissions resolve transitively and are flattened into each role's effective set once at
  build time, so the hot path stays a single set lookup. Cycles are rejected at registration with a
  `RoleInclusionCycleException` rather than looping during a request.
- **Structured denial reasons** (`0.3.0`). A denied `AuthorizationResult` now carries a
  `DenialReason` (a `DenialKind` plus which permission, policy, mode, or resource was at fault)
  alongside the unchanged human-readable string, so callers can branch on the cause instead of
  parsing prose.
- **Batch checks** (`0.3.0`). `AuthorizeAll` and `AuthorizeAllPolicies` evaluate several
  requirements for one principal in a single call, returning a result per requirement and expanding
  the effective set once for the whole batch instead of once per check.
- **Explicit denies** (`0.4.0`). `GrantPrincipal.Denies` carries permission patterns that override a
  matching allow with deny-overrides precedence, applied uniformly across the permission, resource
  (including the ownership and root-wildcard bypass), and policy paths. A deny-driven denial reports
  `DenialKind.ExplicitDeny` with the `DenyPattern` that blocked it.
- **Attribute-based conditions (ABAC)** (`0.4.0`). A policy may carry an optional `GrantCondition`
  predicate evaluated against an `AuthorizationAttributes` context (principal, optional resource, and
  an environment attribute bag) as an AND gate after the permission requirement. Added via
  `AddPolicy(name, mode, condition, permissions)` and the attributes-carrying `AuthorizePolicy` /
  `AuthorizeAllPolicies` overloads; a failed condition reports `DenialKind.ConditionUnmet`. Policies
  with no condition are untouched.
- **Per-principal effective-set caching** (`0.4.0`). Opt-in via
  `OrionGrantBuilder.UseEffectiveSetCache(capacity)`. The authorizer caches each principal's resolved
  effective grant set, keyed on its role / permission / deny membership rather than its subject, so a
  changed membership is a different key and never serves a stale decision. The default
  `BoundedEffectiveGrantCache` is a thread-safe bounded LRU; the pure re-expand-per-check default is
  unchanged when the cache is not enabled.
- **ASP.NET Core integration** (`0.5.0`). A new companion package, `OrionGrant.AspNetCore`, bridges
  OrionGrant to the framework's `[Authorize]` pipeline: an `IAuthorizationHandler` and
  `OrionGrantRequirement` that resolve the current `ClaimsPrincipal` to a `GrantPrincipal` (via a
  pluggable `IGrantPrincipalResolver`, default claims-based) and run the `IGrantAuthorizer` check;
  `RequirePermission` / `RequirePolicy` builder extensions; an `IAuthorizationPolicyProvider` that
  resolves `perm:` / `policy:` policy names; resource-based (object-level) authorization through the
  resource overload of `IAuthorizationService.AuthorizeAsync`; and an
  `OrionGrantAuthorizationFailureReason` that surfaces the structured `DenialReason` on the framework
  failure. The core stays framework-free; this glue lives in its own package. The deny and ABAC
  additions in `0.4.0` supplied the decision semantics it surfaces.

---

## Forward plan

Candidates grouped by the milestone they would most likely land in. Order within a milestone is not fixed.

### Companion packages (alongside the core, framework-free core preserved)

- **Source-generated policy and permission constants.** Generate strongly-typed names from a declared
  policy set so call sites reference symbols instead of magic strings.

### Later theme (toward `1.0`)

- **Decision activity source.** Optional `System.Diagnostics.Activity` tracing alongside the existing
  metrics meter, so an authorization decision can be correlated inside a request trace. The metrics counter
  already ships; this adds spans, not counts.
- **Precompiled permission sets.** Investigate compiling a principal's effective set into a form that
  answers wildcard checks faster than scanning the set per requirement, for read-heavy authorization paths.
  Only if benchmarks show the scan is a real bottleneck after the caching work above.
- **API surface review for 1.0.** Once the items above settle, lock the public surface and commit to
  semantic-versioning stability.

---

## What is intentionally out of scope

To keep the library focused:

- **Permission storage and assignment.** OrionGrant decides; it does not own where roles and grants
  live. Feed it from your own store, JWT claims, or an issuer such as OrionLedger.
- **Authentication.** OrionGrant answers "is this principal allowed", not "who is this principal".
- **A management UI or admin API.** Out of scope for a small, embeddable library.

---

## How to influence this

Open an issue with the `roadmap` label describing the workload you have, not just the feature you
want. Concrete demand is what moves an item from this list into a release.
