# OrionGrant.AspNetCore

ASP.NET Core authorization for OrionGrant: an authorization handler, requirement and policy provider that run OrionGrant permission and policy checks through the standard `[Authorize]` pipeline, including resource-based (object-level) checks and structured denial reasons.

![ASP.NET Core pipeline: the policy provider builds an OrionGrantRequirement, the handler resolves the user to a GrantPrincipal, rejects unsupported resource types, runs IGrantAuthorizer and succeeds or fails the context with OrionGrantAuthorizationFailureReason](https://raw.githubusercontent.com/tunahanaliozturk/OrionGrant/main/docs/diagrams/aspnetcore-pipeline.png)

## Install

    dotnet add package OrionGrant.AspNetCore

Brings in the core `OrionGrant` package and uses the `Microsoft.AspNetCore.App` shared framework. Targets `net8.0`, `net9.0` and `net10.0`.

## Quick start

```csharp
using Moongazing.OrionGrant.AspNetCore;
using Moongazing.OrionGrant.Policies;

builder.Services.AddOrionGrantAuthorization(grant => grant
    .AddRole("orders.manager", "orders:*")
    .AddPolicy("orders.write", PolicyMode.RequireAll, "orders:write"));

builder.Services.AddAuthorization(options =>
    options.AddPolicy("CanReadOrders", policy => policy.RequirePermission("orders:read")));

app.MapGet("/orders", () => "...").RequireAuthorization("CanReadOrders");
app.MapPut("/orders/{id}", (int id) => "...").RequireAuthorization("policy:orders.write");
```

`AddOrionGrantAuthorization` calls `AddAuthorization` and `AddOrionGrant`, registers the handler and the default principal resolver, and replaces `IAuthorizationPolicyProvider` with `OrionGrantPolicyProvider`.

## Policy names

`OrionGrantPolicyProvider` turns `perm:<permission>` into a permission check and `policy:<name>` into an OrionGrant policy check, so `[Authorize(Policy = "perm:orders:read")]` needs no registration per permission. Every other name goes to the framework's default provider. Change the prefixes with `OrionGrantPolicyNameOptions` (`PermissionPrefix`, `PolicyPrefix`; an empty string turns one off).

## Principals from claims

The default `ClaimsGrantPrincipalResolver` reads these claim types from `OrionGrantClaimsOptions`:

| Option | Default | Read into |
|--------|---------|-----------|
| `SubjectClaimType` | `ClaimTypes.NameIdentifier`, then `sub` | `Subject` |
| `RoleClaimType` | `ClaimTypes.Role` | `Roles` |
| `PermissionClaimType` | `permission` | `Permissions` |
| `DenyClaimType` | `deny` | `Denies` |

An unauthenticated user, or one without a subject claim, is denied. Register your own `IGrantPrincipalResolver` before `AddOrionGrantAuthorization` to load grants from another source. Empty claim types fail validation at startup.

## Resources and denials

- Pass an `OrionGrantResource` (a `ResourceContext` plus optional `ResourceAuthorizationOptions`) or a bare `ResourceContext` to `IAuthorizationService.AuthorizeAsync(user, resource, requirement)` for an owner-or-elevated check. For a policy requirement the resource reaches the policy's ABAC condition.
- Any other resource type is denied (fail closed).
- A denial calls `context.Fail` with an `OrionGrantAuthorizationFailureReason` carrying the OrionGrant `AuthorizationResult` and its `DenialReason`, so you can branch on `DenialKind` instead of parsing text.

## Related packages

- `OrionGrant` - the permission, role and policy engine this package wires in.

## Links

- Documentation and full README: https://github.com/tunahanaliozturk/OrionGrant
- Changelog: https://github.com/tunahanaliozturk/OrionGrant/blob/main/CHANGELOG.md
- License: MIT
