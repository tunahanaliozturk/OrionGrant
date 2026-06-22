# OrionGrant Roadmap

Where OrionGrant is, what has shipped, and what is likely next.

OrionGrant is at `0.3.0`: a dependency-light permission and policy authorization library for .NET, with
hierarchical wildcard permissions, roles (including role-to-role composition), named all-of / any-of
policies, resource / ownership-aware (object-level) checks, structured denial reasons, and batch checks.
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

---

## Forward plan

Candidates grouped by the milestone they would most likely land in. Order within a milestone is not fixed.

### Next minor (`0.4.0`, targeting Q4 2026)

- **Effective-set caching per principal.** `EffectivePermissions` rebuilds a set on every call. Add an
  optional cache keyed on a principal's roles and direct permissions, for call sites that authorize the
  same principal many times in one request. Opt-in, so the pure default stays allocation-light.
- **Explicit denies.** A way to subtract a permission from an otherwise-granted set, for carve-outs. Needs
  a clear, documented precedence rule (deny over grant) before it would be worth adding.
- **Attribute conditions (ABAC).** Optional predicate conditions on a policy evaluated against the
  `ResourceContext` (and principal), for rules that depend on resource attributes rather than ownership
  alone. Scoped so the permission and policy fast paths stay untouched when no condition is present.

### Companion packages (alongside the above, framework-free core preserved)

- **ASP.NET Core integration.** An `AuthorizationHandler` / requirement that bridges OrionGrant policies to
  the framework's `[Authorize]` pipeline, plus result helpers that turn a denied `AuthorizationResult` into
  a `ForbidResult` or an RFC 9457 ProblemDetails payload. Kept in its own package so the core stays
  framework-free.
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
