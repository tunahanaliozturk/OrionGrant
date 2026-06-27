namespace Moongazing.OrionGrant.Tests;

using System;
using System.Collections.Generic;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of attribute-based (ABAC) policy conditions. A condition is an additional AND gate on a
/// policy: the permission requirement is evaluated first, and the condition allows or denies based on
/// principal, resource, and environment attributes. A policy with no condition is unchanged from
/// 0.3.0, and a denied condition reports <see cref="DenialKind.ConditionUnmet"/>.
/// </summary>
public sealed class AbacConditionTests
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
    public void Condition_allows_when_attribute_satisfies_predicate()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.read.business-hours",
            PolicyMode.RequireAll,
            attrs => attrs.Env("hour") == "10",
            "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var attributes = new AuthorizationAttributes(
            principal,
            environment: new Dictionary<string, string?> { ["hour"] = "10" });

        Assert.True(authorizer.AuthorizePolicy(principal, "orders.read.business-hours", attributes).IsGranted);
    }

    [Fact]
    public void Condition_denies_when_attribute_fails_predicate()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.read.business-hours",
            PolicyMode.RequireAll,
            attrs => attrs.Env("hour") == "10",
            "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var attributes = new AuthorizationAttributes(
            principal,
            environment: new Dictionary<string, string?> { ["hour"] = "23" });

        var result = authorizer.AuthorizePolicy(principal, "orders.read.business-hours", attributes);

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ConditionUnmet, result.Denial!.Kind);
        Assert.Equal("orders.read.business-hours", result.Denial.PolicyName);
    }

    [Fact]
    public void Permission_gate_is_evaluated_before_the_condition()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.read.business-hours",
            PolicyMode.RequireAll,
            _ => true,
            "orders:read"));

        // The principal lacks the permission; the policy must fail on the permission requirement,
        // not slip through because the condition is trivially true.
        var principal = new GrantPrincipal { Subject = "u1" };
        var result = authorizer.AuthorizePolicy(principal, "orders.read.business-hours", AuthorizationAttributes.For(principal));

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.PolicyRequirementUnmet, result.Denial!.Kind);
    }

    [Fact]
    public void Condition_composes_with_a_require_any_policy()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.touch.owner",
            PolicyMode.RequireAny,
            attrs => attrs.Resource is { OwnerId: "u1" },
            "orders:read",
            "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:write"] };

        var owned = new AuthorizationAttributes(principal, ResourceContext.OwnedBy("u1"));
        Assert.True(authorizer.AuthorizePolicy(principal, "orders.touch.owner", owned).IsGranted);

        var notOwned = new AuthorizationAttributes(principal, ResourceContext.OwnedBy("u2"));
        Assert.False(authorizer.AuthorizePolicy(principal, "orders.touch.owner", notOwned).IsGranted);
    }

    [Fact]
    public void Condition_can_read_principal_attributes()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.read.self",
            PolicyMode.RequireAll,
            attrs => attrs.Principal.Subject == "u1",
            "orders:read"));
        var allowed = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var blocked = new GrantPrincipal { Subject = "u2", Permissions = ["orders:read"] };

        Assert.True(authorizer.AuthorizePolicy(allowed, "orders.read.self").IsGranted);
        Assert.False(authorizer.AuthorizePolicy(blocked, "orders.read.self").IsGranted);
    }

    [Fact]
    public void Null_attributes_synthesize_a_principal_only_context()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.read.self",
            PolicyMode.RequireAll,
            attrs => attrs.Principal.Subject == "u1" && attrs.Resource is null,
            "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        // The two-argument overload passes null attributes; the authorizer synthesizes a context
        // from the principal with no resource and no environment.
        Assert.True(authorizer.AuthorizePolicy(principal, "orders.read.self").IsGranted);
    }

    [Fact]
    public void A_policy_with_no_condition_ignores_supplied_attributes()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.read",
            PolicyMode.RequireAll,
            "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var attributes = new AuthorizationAttributes(
            principal,
            environment: new Dictionary<string, string?> { ["anything"] = "ignored" });

        Assert.True(authorizer.AuthorizePolicy(principal, "orders.read", attributes).IsGranted);
    }

    [Fact]
    public void Condition_and_deny_compose_deny_wins()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy(
            "orders.read.business-hours",
            PolicyMode.RequireAll,
            _ => true,
            "orders:read"));
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read"],
            Denies = ["orders:read"],
        };

        // The deny removes the permission, so the policy fails before the (true) condition runs.
        var result = authorizer.AuthorizePolicy(principal, "orders.read.business-hours", AuthorizationAttributes.For(principal));

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, result.Denial!.Kind);
    }

    [Fact]
    public void AddPolicy_with_condition_rejects_a_null_condition()
    {
        var builder = new OrionGrantBuilder();

        Assert.Throws<ArgumentNullException>(() =>
            builder.AddPolicy("p", PolicyMode.RequireAll, (GrantCondition)null!, "orders:read"));
    }
}
