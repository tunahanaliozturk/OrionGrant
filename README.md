<p align="center">
  <img src="docs/logo.png" alt="OrionGrant" width="150" />
</p>

<h1 align="center">OrionGrant</h1>

<p align="center">
  Permission and policy authorization for .NET, with no framework dependency.
</p>

<p align="center">
  <a href="https://github.com/tunahanaliozturk/OrionGrant/actions/workflows/ci-cd.yml"><img src="https://github.com/tunahanaliozturk/OrionGrant/actions/workflows/ci-cd.yml/badge.svg" alt="CI/CD" /></a>
  <a href="https://www.nuget.org/packages/OrionGrant/"><img src="https://img.shields.io/nuget/v/OrionGrant.svg" alt="NuGet" /></a>
</p>

---

Define permissions as colon-scoped hierarchies with wildcards, group them into roles, and check
whether a principal is allowed an action, either by a single permission or by a named policy. The
matching rules are pure functions you can unit-test, and the library depends only on
`Microsoft.Extensions.DependencyInjection.Abstractions`.

Part of the **Orion** family. Pairs naturally with [OrionLedger](https://github.com/tunahanaliozturk/OrionLedger)
API-key scopes (feed the issued scopes straight into a principal's permissions), and works entirely
on its own.

## Why

Most apps grow an ad-hoc tangle of `if (user.IsAdmin || user.Roles.Contains(...))`. OrionGrant
replaces that with a small, testable model:

- permissions like `orders:read`,
- wildcards like `orders:*`,
- roles that bundle permissions,
- and policies that combine requirements under a stable name.

The matcher and the authorizer are pure and synchronous, so authorization is allocation-light and
trivially unit-testable, and there is no external service to stand up.

## Features

- **Hierarchical permissions.** Colon-scoped strings (`orders:eu:write`) with wildcard matching:
  `*` matches one segment in the middle, or one-or-more segments when it is the last segment.
- **Roles.** A role bundles permissions. A principal's effective set is its direct permissions
  unioned with the permissions of every role it holds. Unknown roles contribute nothing.
- **Named policies.** `RequireAll` needs every listed permission; `RequireAny` needs at least one.
  Endpoints depend on the policy name, so you can change what it requires without touching call
  sites.
- **Resource / ownership-aware authorization.** Object-level checks where access is granted to the
  resource's owner OR to a principal holding a configured elevated permission. Holding `accounts:read`
  is necessary but not sufficient to read an account you do not own, which closes the IDOR gap.
- **A clear decision type.** Every check returns an `AuthorizationResult` carrying a granted flag
  and, on denial, a human-readable reason suitable for logging and a 403 body.
- **Telemetry built in.** A `System.Diagnostics.Metrics` meter counts every decision, tagged by
  outcome and kind.
- **No framework coupling.** Pure, synchronous, allocation-light. Multi-targets `net8.0`, `net9.0`,
  and `net10.0`.

See [docs/FEATURES.md](docs/FEATURES.md) for the full breakdown of the public surface, and
[docs/ROADMAP.md](docs/ROADMAP.md) for what is under consideration.

## Install

```
dotnet add package OrionGrant
```

## Quick start

Register roles and policies once at startup:

```csharp
builder.Services.AddOrionGrant(grant => grant
    .AddRole("orders.manager", "orders:*")
    .AddRole("auditor", "orders:read", "billing:read")
    .AddPolicy("orders.write", PolicyMode.RequireAll, "orders:write")
    .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
```

Inject `IGrantAuthorizer` and check a permission or a policy:

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

A principal is just a subject plus the roles and direct permissions it carries (build it from your
API key, JWT claims, or session):

```csharp
var caller = new GrantPrincipal
{
    Subject = apiKey.Id,
    Roles = apiKey.Roles,
    Permissions = apiKey.Scopes,   // e.g. straight from OrionLedger
};
```

## Usage

### Permission matching

Permissions are colon-separated. A `*` segment matches one segment in the middle, or one-or-more
segments when it is last:

| Granted | Covers | Does not cover |
|---------|--------|----------------|
| `orders:read` | `orders:read` | `orders:write`, `orders:read:detail` |
| `orders:*` | `orders:read`, `orders:read:detail` | `orders`, `billing:read` |
| `orders:*:read` | `orders:eu:read` | `orders:eu:write` |
| `*` | everything | nothing |

The rules live in the static, pure `PermissionMatcher`, so you can use them directly without the DI
container or an authorizer:

```csharp
PermissionMatcher.IsGranted("orders:*", "orders:read");                 // true
PermissionMatcher.IsGrantedByAny(["billing:read", "orders:*"], "orders:write"); // true
```

### Roles

A **role** bundles permissions. The authorizer expands every role a principal holds and unions the
results with the principal's direct permissions to get the effective set. Calling `AddRole` again
for the same name adds to that role's permission set rather than replacing it:

```csharp
builder.Services.AddOrionGrant(grant => grant
    .AddRole("support", "tickets:read")
    .AddRole("support", "tickets:comment"));   // support now grants both
```

You can inspect the effective set for a principal directly:

```csharp
IReadOnlySet<string> effective = authorizer.EffectivePermissions(caller);
```

### Policies: RequireAll and RequireAny

A **policy** is a named requirement evaluated against the principal's effective permissions:

- `PolicyMode.RequireAll` grants only when every listed permission is satisfied.
- `PolicyMode.RequireAny` grants when at least one is satisfied (it short-circuits on the first
  match).

```csharp
builder.Services.AddOrionGrant(grant => grant
    .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write")
    .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));

var manage = authorizer.AuthorizePolicy(caller, "orders.manage");
var touch  = authorizer.AuthorizePolicy(caller, "orders.touch");
```

Each listed permission is checked through the same wildcard matcher, so a principal holding
`orders:*` satisfies a policy that lists `orders:read` and `orders:write`. An unknown policy name is
denied with a reason rather than throwing.

### Resource and ownership-aware authorization

A permission check answers "may this principal read accounts?". It does not answer "may this
principal read *this* account?". Granting `accounts:read` to every caller and reading whatever id
arrives is the classic IDOR (Insecure Direct Object Reference) bug: one user reads another user's
row by changing a number in the URL.

The resource-aware overload closes that gap. The principal must hold the permission AND either own
the resource or hold a configured elevated grant. Holding the permission alone is necessary but not
sufficient:

```csharp
// account 42 is owned by u1; the owner id is what gets compared to the principal subject.
var account = new ResourceContext(ownerId: "u1", resourceType: "account", resourceId: "42");

var owner    = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };
var stranger = new GrantPrincipal { Subject = "u2", Permissions = ["accounts:read"] };

authorizer.Authorize(owner,    "accounts:read", account).IsGranted;   // true  - holds it and owns it
authorizer.Authorize(stranger, "accounts:read", account).IsGranted;   // false - holds it but does not own it
```

`ResourceContext.OwnedBy("u1")` is a shorthand when only the owner identity matters. The optional
`resourceType` and `resourceId` are not used in the decision; they are carried for logging and
diagnostics so a denial can be traced to a concrete resource.

The "owner OR elevated" pattern lets privileged callers bypass ownership. Configure it per call with
`ResourceAuthorizationOptions`:

```csharp
var options = new ResourceAuthorizationOptions
{
    ElevatedPermissions = ["accounts:read:any"],   // any caller granted this bypasses ownership
};

var support = new GrantPrincipal { Subject = "svc-support", Permissions = ["accounts:read", "accounts:read:any"] };
authorizer.Authorize(support, "accounts:read", account, options).IsGranted;   // true - elevated bypass
```

Elevated permissions are matched through the same wildcard matcher as everything else.
`OwnerComparison` controls how the subject and owner id are compared (`StringComparison.Ordinal` by
default, matching the rest of the library). `TreatRootWildcardAsElevated` is on by default, so a
principal holding the root `*` grant bypasses ownership with no per-call configuration:

```csharp
var admin = new GrantPrincipal { Subject = "svc-admin", Permissions = ["*"] };
authorizer.Authorize(admin, "accounts:read", account).IsGranted;   // true - root bypasses ownership
```

The overload is a default interface method on `IGrantAuthorizer`, so existing implementors keep
compiling. Resource-aware decisions are recorded on the `oriongrant.decisions` counter with
`kind=resource`.

## Configuration

Everything is wired through `AddOrionGrant`. The `configure` callback is optional; calling
`AddOrionGrant()` with no arguments registers a working authorizer with no roles or policies
defined.

| Registered service | Lifetime | Notes |
|--------------------|----------|-------|
| `IGrantAuthorizer` | Singleton | The entry point for all checks. |
| `RoleRegistry` | Singleton | Immutable role-to-permissions map, built once from the builder. |
| `PolicyRegistry` | Singleton | Immutable name-to-policy map, built once from the builder. |
| `GrantDiagnostics` | Singleton | Owns the metrics meter; disposed with the container. |

Registrations use `TryAdd`, so you can register your own implementation of any of these before
calling `AddOrionGrant` and it will be respected. Roles and policies are resolved once at
registration into immutable registries, so configuration is read at startup, not per request.

## Telemetry

`GrantDiagnostics` exposes a `System.Diagnostics.Metrics` meter named `Moongazing.OrionGrant`
(also available as `GrantDiagnostics.MeterName`). It publishes one counter:

- `oriongrant.decisions` (unit `{decision}`) tagged `outcome` (`granted` / `denied`) and `kind`
  (`permission` / `policy`).

Subscribe to it from OpenTelemetry like any other meter:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics.AddMeter(GrantDiagnostics.MeterName));
```

## Testing

The matcher and the authorizer are pure and synchronous, so unit tests need no mocks and no host.
Construct a `GrantAuthorizer` directly from a builder, or drive `PermissionMatcher` on its own:

```csharp
var builder = new OrionGrantBuilder();
builder.AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write");

using var diagnostics = new GrantDiagnostics();
var authorizer = new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), diagnostics);

var full = new GrantPrincipal { Subject = "u1", Permissions = ["orders:*"] };
Assert.True(authorizer.AuthorizePolicy(full, "orders.manage").IsGranted);
```

The repository's own test suite (xUnit) lives in `tests/`. There is also a BenchmarkDotNet suite in
`benchmarks/` covering the matcher, the authorizer, and the one-time registration path; see
[benchmarks.md](benchmarks.md). No measured numbers are committed; collect your own on the hardware
you care about.

## Versioning

OrionGrant follows [Semantic Versioning](https://semver.org/). The current line is `0.1.0`
(pre-1.0): the public API may still change between minor versions while the design settles. The
library multi-targets `net8.0`, `net9.0`, and `net10.0`, builds with `TreatWarningsAsErrors`,
nullable reference types enabled, and `latest-recommended` analyzers. See [CHANGELOG.md](CHANGELOG.md)
for release notes.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening one.

## More from the Orion family

OrionGrant is one of a set of standalone .NET libraries:

- [OrionGuard](https://github.com/tunahanaliozturk/OrionGuard) - guard clauses and validation.
- [OrionLedger](https://github.com/tunahanaliozturk/OrionLedger) - API-key issuance and scopes.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

**Tunahan Ali Ozturk** - [GitHub](https://github.com/tunahanaliozturk)
</content>
