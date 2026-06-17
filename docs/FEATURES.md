# OrionGrant Features

A deep, accurate walk through OrionGrant's public surface. Everything here is in the
`Moongazing.OrionGrant` package (NuGet id `OrionGrant`) and matches the shipped API.

---

## Table of contents

1. [The model](#1-the-model)
2. [Permissions and wildcard matching](#2-permissions-and-wildcard-matching)
3. [Principals](#3-principals)
4. [Roles and the role registry](#4-roles-and-the-role-registry)
5. [Policies: RequireAll and RequireAny](#5-policies-requireall-and-requireany)
6. [The authorizer](#6-the-authorizer)
7. [Authorization results](#7-authorization-results)
8. [Registration and DI](#8-registration-and-di)
9. [Telemetry](#9-telemetry)
10. [Build and targeting](#10-build-and-targeting)

---

## 1. The model

OrionGrant has four moving parts:

- a **permission**, a colon-scoped string such as `orders:read` or `orders:eu:write`;
- a **role**, a name that bundles a set of permissions;
- a **policy**, a named requirement that combines permissions with an all-of or any-of rule;
- a **principal**, the subject of a decision, carrying the roles and direct permissions it holds.

A decision expands the principal's roles into permissions, unions them with its direct permissions,
and matches the result against either a single required permission or a named policy. Every piece is
pure and synchronous, so the whole thing is allocation-light and unit-testable without a host.

---

## 2. Permissions and wildcard matching

`PermissionMatcher` is a static class with two pure methods:

```csharp
bool IsGranted(string pattern, string required);
bool IsGrantedByAny(IEnumerable<string> granted, string required);
```

Permissions are split on `:`. Matching walks pattern segments against required segments:

- A literal segment must equal the corresponding required segment (ordinal comparison).
- A `*` segment that is **not** the last segment matches exactly one required segment.
- A `*` segment that **is** the last segment matches one or more remaining required segments.
- With no trailing wildcard, the segment counts must line up exactly.

This yields the following behavior (all verified by the test suite):

| Granted pattern | Required | Result |
|-----------------|----------|--------|
| `orders:read` | `orders:read` | granted |
| `orders:read` | `orders:write` | denied |
| `orders:read` | `orders:read:detail` | denied |
| `orders:read:detail` | `orders:read` | denied |
| `orders:*` | `orders:read` | granted |
| `orders:*` | `orders:read:detail` | granted |
| `orders:*` | `orders` | denied |
| `orders:*:read` | `orders:eu:read` | granted |
| `orders:*:read` | `orders:eu:write` | denied |
| `*` | anything | granted |

`IsGrantedByAny` returns true if any pattern in the set covers the required permission. Empty or null
patterns in the set are skipped rather than throwing. Both methods throw `ArgumentException` on a
null or empty `required` value.

Because the matcher is static and dependency-free, you can use it directly in domain code, tests, or
tooling without touching the DI container.

---

## 3. Principals

`GrantPrincipal` is the subject of a decision:

```csharp
public sealed class GrantPrincipal
{
    public required string Subject { get; init; }
    public IReadOnlyCollection<string> Roles { get; init; } = [];
    public IReadOnlyCollection<string> Permissions { get; init; } = [];
}
```

- `Subject` is a stable identifier (a user id, an API key id, a service name). It is required.
- `Roles` are expanded through the role registry; unknown roles are ignored.
- `Permissions` are granted to the subject directly, in addition to those it inherits from roles.

Build a principal from whatever your application already trusts: API-key scopes (for example issued
by OrionLedger), JWT claims, or a session.

---

## 4. Roles and the role registry

A role bundles permissions. Roles are declared on the builder and frozen into an immutable
`RoleRegistry` at registration.

```csharp
public sealed class RoleRegistry
{
    public static RoleRegistry Empty { get; }
    public IReadOnlySet<string> PermissionsFor(string role);  // empty set for unknown roles
    public IEnumerable<string> Roles { get; }
}
```

`PermissionsFor` returns the role's permissions, or an empty set if the role is unknown, so an
unknown role on a principal simply contributes nothing rather than failing the decision. Role names
are compared with `StringComparer.Ordinal`.

---

## 5. Policies: RequireAll and RequireAny

A policy is a named requirement modeled by `AccessPolicy` and the `PolicyMode` enum:

```csharp
public enum PolicyMode
{
    RequireAll,  // principal must hold every listed permission
    RequireAny,  // principal must hold at least one listed permission
}
```

`AccessPolicy` carries the name, the mode, and the listed permissions. A policy must list at least
one permission; constructing one with an empty list throws `ArgumentException`. Policies are frozen
into an immutable `PolicyRegistry` at registration:

```csharp
public sealed class PolicyRegistry
{
    public static PolicyRegistry Empty { get; }
    public AccessPolicy? Find(string name);   // null when undefined
}
```

The point of a named policy is indirection: an endpoint depends on `orders.manage`, and you can
change which permissions that requires without editing the endpoint.

---

## 6. The authorizer

`IGrantAuthorizer` is the entry point:

```csharp
public interface IGrantAuthorizer
{
    AuthorizationResult Authorize(GrantPrincipal principal, string requiredPermission);
    AuthorizationResult AuthorizePolicy(GrantPrincipal principal, string policyName);
    IReadOnlySet<string> EffectivePermissions(GrantPrincipal principal);
}
```

The default `GrantAuthorizer`:

- `EffectivePermissions` builds the union of the principal's direct permissions and the permissions
  of every role it holds (skipping empty role names), returning an ordinal `HashSet`.
- `Authorize` checks a single required permission against that effective set via
  `PermissionMatcher.IsGrantedByAny`, records a `permission` decision, and returns granted or a
  denial reason naming the missing permission.
- `AuthorizePolicy` looks the policy up by name. An unknown policy is denied with a reason (and
  recorded as a denied `policy` decision). Otherwise it evaluates the mode: `RequireAny`
  short-circuits on the first satisfied permission; `RequireAll` denies on the first unsatisfied
  permission, naming it in the reason. Each listed permission is checked through the same wildcard
  matcher.

All methods validate their arguments (`ArgumentNullException` for a null principal,
`ArgumentException` for a null or empty permission or policy name).

---

## 7. Authorization results

Every check returns an `AuthorizationResult`:

```csharp
public sealed class AuthorizationResult
{
    public bool IsGranted { get; }
    public string? FailureReason { get; }       // null when granted
    public static AuthorizationResult Granted { get; }
    public static AuthorizationResult Denied(string reason);
}
```

`Granted` is a shared singleton. `Denied` carries a human-readable reason intended for logging and
for a 403 response body; the reason names the missing permission or policy, so the caller does not
have to reconstruct why the check failed.

---

## 8. Registration and DI

`AddOrionGrant` wires everything into the service collection:

```csharp
public static IServiceCollection AddOrionGrant(
    this IServiceCollection services,
    Action<OrionGrantBuilder>? configure = null);
```

The `configure` callback is optional. It registers, all as singletons via `TryAdd`:

- the `RoleRegistry` built from the declared roles,
- the `PolicyRegistry` built from the declared policies,
- a `GrantDiagnostics` instance,
- an `IGrantAuthorizer` (the default `GrantAuthorizer`).

Because registration uses `TryAdd`, registering your own implementation of any of these before
calling `AddOrionGrant` is respected.

The builder is fluent:

```csharp
public sealed class OrionGrantBuilder
{
    public OrionGrantBuilder AddRole(string role, params string[] permissions);
    public OrionGrantBuilder AddPolicy(string name, PolicyMode mode, params string[] permissions);
}
```

`AddRole` is additive: calling it again for the same role name adds to that role's permission set.
Empty permission strings are ignored. `AddPolicy` registers a named policy under its name (the last
definition for a given name wins). The builder is evaluated once at registration to produce the
immutable registries, so there is no per-request configuration cost.

---

## 9. Telemetry

`GrantDiagnostics` owns a `System.Diagnostics.Metrics.Meter` named `Moongazing.OrionGrant` (exposed
as `GrantDiagnostics.MeterName`). It publishes a single counter:

- `oriongrant.decisions`, unit `{decision}`, tagged `outcome` (`granted` / `denied`) and `kind`
  (`permission` / `policy`).

The authorizer records one decision per `Authorize` and `AuthorizePolicy` call, including denials
for unknown policies. Subscribe from OpenTelemetry with `AddMeter(GrantDiagnostics.MeterName)`.
`GrantDiagnostics` is `IDisposable` and disposes the meter; the DI container handles that for the
singleton it registers.

---

## 10. Build and targeting

- Multi-targets `net8.0`, `net9.0`, and `net10.0`.
- Nullable reference types enabled, implicit usings enabled.
- `TreatWarningsAsErrors`, `EnforceCodeStyleInBuild`, `AnalysisLevel` `latest-recommended`.
- XML documentation generated for the public API.
- The only runtime dependency is `Microsoft.Extensions.DependencyInjection.Abstractions`.
</content>
