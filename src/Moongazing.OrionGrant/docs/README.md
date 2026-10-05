# OrionGrant

Permission and policy authorization for .NET: colon-scoped permissions with wildcards, roles that compose, named all-of / any-of policies, explicit denies, ABAC conditions and owner-aware (IDOR-resistant) checks. Pure, synchronous and free of any web framework.

![Permission check: build the effective grant set; a matching deny gives ExplicitDeny, no matching allow gives MissingPermission, otherwise granted; the resource overload then grants an elevated principal or the owner and denies anyone else with ResourceOwnership](https://raw.githubusercontent.com/tunahanaliozturk/OrionGrant/main/docs/diagrams/permission-check.png)

## Install

    dotnet add package OrionGrant

Targets `net8.0`, `net9.0` and `net10.0`. Depends on `Microsoft.Extensions.DependencyInjection.Abstractions` and `Orion.Abstractions`.

## Quick start

```csharp
using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Policies;

builder.Services.AddOrionGrant(grant => grant
    .AddRole("orders.manager", "orders:*")
    .AddRole("auditor", "orders:read", "billing:read")
    .AddPolicy("orders.write", PolicyMode.RequireAll, "orders:write"));

public sealed class OrderService(IGrantAuthorizer authorizer)
{
    public void Update(GrantPrincipal caller, Order order)
    {
        var decision = authorizer.AuthorizePolicy(caller, "orders.write");
        if (!decision.IsGranted)
        {
            throw new UnauthorizedAccessException(decision.FailureReason);
        }
        // ...
    }
}
```

A `GrantPrincipal` is a `Subject` plus the `Roles`, direct `Permissions` and `Denies` it carries, built from claims, an API key or a session.

## Permission matching

| Granted | Covers | Does not cover |
|---------|--------|----------------|
| `orders:read` | `orders:read` | `orders:write`, `orders:read:detail` |
| `orders:*` | `orders:read`, `orders:read:detail` | `orders`, `billing:read` |
| `orders:*:read` | `orders:eu:read` | `orders:eu:write` |
| `*` | everything | nothing |

The rules live in the static `PermissionMatcher` (`IsGranted`, `IsGrantedByAny`), usable without DI.

## What a check does

- **Roles**: `AddRole` bundles permissions; `IncludeRole` composes roles transitively. Inclusion cycles throw `RoleInclusionCycleException` at registration. Unknown roles grant nothing.
- **Denies win**: a pattern in `GrantPrincipal.Denies` overrides any matching allow, ownership and elevation.
- **Policies**: `RequireAll` needs every listed permission, `RequireAny` at least one. `AddPolicy(name, mode, condition, permissions)` adds a `GrantCondition` over `AuthorizationAttributes` (principal, resource, environment), AND-ed with the permissions.
- **Resource-aware**: `Authorize(principal, permission, resource, options)` also needs the principal to own the resource (`ResourceContext.OwnerId` equals `Subject`, `StringComparison.Ordinal` by default) or hold an elevated grant (root `*` by default, or `ResourceAuthorizationOptions.ElevatedPermissions`).
- **Batch**: `AuthorizeAll` and `AuthorizeAllPolicies` expand the effective set once for many checks.
- **Cache**: `UseEffectiveSetCache(capacity)` (default 1024) caches expanded grant sets; off by default.

## Results, not exceptions

Every check returns an `AuthorizationResult`: `IsGranted`, a human-readable `FailureReason`, and a structured `Denial` whose `DenialKind` is `MissingPermission`, `PolicyNotFound`, `PolicyRequirementUnmet`, `ResourceOwnership`, `ExplicitDeny` or `ConditionUnmet`. An unknown policy is a denial, not an exception.

## Telemetry

Meter `Moongazing.OrionGrant` (`GrantDiagnostics.MeterName`) with counter `orion.grant.decisions`, tagged `orion.outcome` (`granted` / `denied`) and `kind` (`permission` / `policy` / `resource`).

## Related packages

- `OrionGrant.AspNetCore` - runs these checks through ASP.NET Core `[Authorize]`, with `perm:` / `policy:` policy names and claims-based principals.
- `Orion.Abstractions` - the Orion family's shared contracts and telemetry spine.

## Links

- Documentation and full README: https://github.com/tunahanaliozturk/OrionGrant
- Changelog: https://github.com/tunahanaliozturk/OrionGrant/blob/main/CHANGELOG.md
- License: MIT
