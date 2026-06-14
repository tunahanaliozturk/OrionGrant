# OrionGrant

[![CI/CD](https://github.com/tunahanaliozturk/OrionGrant/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/tunahanaliozturk/OrionGrant/actions/workflows/ci-cd.yml)
[![NuGet](https://img.shields.io/nuget/v/OrionGrant.svg)](https://www.nuget.org/packages/OrionGrant/)

Permission and policy authorization for .NET. Define permissions as colon-scoped hierarchies with
wildcards, group them into roles, and check whether a principal is allowed an action, either by a
single permission or by a named policy.

Part of the **Orion** family. Pairs naturally with [OrionLedger](https://github.com/tunahanaliozturk/OrionLedger)
API-key scopes, and works entirely on its own.

## Why

Most apps grow an ad-hoc tangle of `if (user.IsAdmin || user.Roles.Contains(...))`. OrionGrant
replaces that with a small, testable model: permissions like `orders:read`, wildcards like
`orders:*`, roles that bundle permissions, and policies that combine requirements. The matching
rules are pure functions you can unit-test, and the whole thing has no framework dependency.

## Install

```
dotnet add package OrionGrant
```

## Quick start

```csharp
builder.Services.AddOrionGrant(grant => grant
    .AddRole("orders.manager", "orders:*")
    .AddRole("auditor", "orders:read", "billing:read")
    .AddPolicy("orders.write", PolicyMode.RequireAll, "orders:write")
    .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
```

```csharp
public sealed class OrdersController(IGrantAuthorizer authorizer)
{
    public IActionResult Update(GrantPrincipal caller)
    {
        var decision = authorizer.AuthorizePolicy(caller, "orders.write");
        if (!decision.IsGranted)
        {
            return Forbid(decision.FailureReason!);
        }
        // ...
    }
}
```

A principal is just a subject plus the roles and direct permissions it carries (build it from
your API key, JWT claims, or session):

```csharp
var caller = new GrantPrincipal
{
    Subject = apiKey.Id,
    Roles = apiKey.Roles,
    Permissions = apiKey.Scopes,   // e.g. straight from OrionLedger
};
```

## Permission matching

Permissions are colon-separated. A `*` segment matches one segment in the middle, or one-or-more
segments when it is last:

| Granted | Covers | Does not cover |
|---------|--------|----------------|
| `orders:read` | `orders:read` | `orders:write`, `orders:read:detail` |
| `orders:*` | `orders:read`, `orders:read:detail` | `orders`, `billing:read` |
| `orders:*:read` | `orders:eu:read` | `orders:eu:write` |
| `*` | everything | nothing |

## Roles and policies

A **role** bundles permissions; a principal's effective set is its direct permissions unioned with
every role it holds (unknown roles contribute nothing). A **policy** is a named requirement:
`RequireAll` needs every listed permission, `RequireAny` needs at least one. Endpoints depend on a
policy name, so you can change what it requires without touching call sites.

## Telemetry

Subscribe to the `Moongazing.OrionGrant` meter: `oriongrant.decisions` is tagged `outcome`
(granted/denied) and `kind` (permission/policy).

## Design

- Multi-targets `net8.0`, `net9.0`, `net10.0`.
- `TreatWarningsAsErrors`, latest analyzers, nullable enabled.
- The matcher and the authorizer are pure and synchronous, so authorization is allocation-light
  and trivially unit-testable.

## License

MIT.
