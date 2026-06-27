namespace Moongazing.OrionGrant.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage that batch checks honor the v0.4.0 additions: <see cref="GrantAuthorizer.AuthorizeAll"/>
/// applies explicit denies per item, and the attributes-carrying
/// <see cref="GrantAuthorizer.AuthorizeAllPolicies(GrantPrincipal, IReadOnlyCollection{string}, AuthorizationAttributes?)"/>
/// applies both denies and ABAC conditions. Each batch item must match the equivalent single check,
/// so batch stays an optimization rather than a behavior change.
/// </summary>
public sealed class BatchDenyConditionTests
{
    private static GrantAuthorizer Build(
        GrantDiagnostics diagnostics,
        Action<OrionGrantBuilder>? configure = null)
    {
        var builder = new OrionGrantBuilder();
        configure?.Invoke(builder);
        return new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), diagnostics);
    }

    [Fact]
    public void AuthorizeAll_applies_denies_per_item()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read", "orders:write", "billing:read"],
            Denies = ["orders:write"],
        };

        var results = authorizer.AuthorizeAll(principal, ["orders:read", "orders:write", "billing:read"]);

        Assert.True(results[0].IsGranted);
        Assert.False(results[1].IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, results[1].Result.Denial!.Kind);
        Assert.True(results[2].IsGranted);
    }

    [Fact]
    public void AuthorizeAll_each_item_matches_the_single_check_under_denies()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("ops", "orders:*"));
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Roles = ["ops"],
            Denies = ["orders:delete"],
        };
        string[] checks = ["orders:read", "orders:delete", "orders:write"];

        var batch = authorizer.AuthorizeAll(principal, checks);

        foreach (var (entry, permission) in batch.Zip(checks))
        {
            var single = authorizer.Authorize(principal, permission);
            Assert.Equal(single.IsGranted, entry.IsGranted);
            Assert.Equal(single.Denial?.Kind, entry.Result.Denial?.Kind);
        }
    }

    [Fact]
    public void AuthorizeAllPolicies_applies_denies_and_conditions_per_item()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("plain", PolicyMode.RequireAll, "orders:read")
            .AddPolicy("conditioned", PolicyMode.RequireAll, attrs => attrs.Env("region") == "eu", "orders:read")
            .AddPolicy("denied", PolicyMode.RequireAll, "orders:write"));
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read", "orders:write"],
            Denies = ["orders:write"],
        };
        var attributes = new AuthorizationAttributes(
            principal,
            environment: new Dictionary<string, string?> { ["region"] = "us" });

        var results = authorizer.AuthorizeAllPolicies(principal, ["plain", "conditioned", "denied"], attributes);

        // plain: permission held, no condition -> granted.
        Assert.True(results[0].IsGranted);

        // conditioned: permission held but region is us, not eu -> condition unmet.
        Assert.False(results[1].IsGranted);
        Assert.Equal(DenialKind.ConditionUnmet, results[1].Result.Denial!.Kind);

        // denied: permission is explicitly denied -> explicit deny.
        Assert.False(results[2].IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, results[2].Result.Denial!.Kind);
    }

    [Fact]
    public void AuthorizeAllPolicies_each_item_matches_the_single_check()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("conditioned", PolicyMode.RequireAll, attrs => attrs.Env("region") == "eu", "orders:read")
            .AddPolicy("plain", PolicyMode.RequireAny, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var attributes = new AuthorizationAttributes(
            principal,
            environment: new Dictionary<string, string?> { ["region"] = "eu" });
        string[] names = ["conditioned", "plain"];

        var batch = authorizer.AuthorizeAllPolicies(principal, names, attributes);

        foreach (var (entry, name) in batch.Zip(names))
        {
            var single = authorizer.AuthorizePolicy(principal, name, attributes);
            Assert.Equal(single.IsGranted, entry.IsGranted);
            Assert.Equal(single.Denial?.Kind, entry.Result.Denial?.Kind);
        }
    }

    [Fact]
    public void AuthorizeAllPolicies_without_attributes_treats_conditions_with_a_principal_only_context()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("self", PolicyMode.RequireAll, attrs => attrs.Principal.Subject == "u1", "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        // The two-argument batch overload passes null attributes; the principal-only context still
        // satisfies a condition that reads only the principal.
        var results = authorizer.AuthorizeAllPolicies(principal, ["self"]);

        Assert.True(results[0].IsGranted);
    }
}
