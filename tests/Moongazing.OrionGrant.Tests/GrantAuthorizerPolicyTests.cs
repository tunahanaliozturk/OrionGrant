namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of <see cref="GrantAuthorizer.AuthorizePolicy"/>: RequireAll and RequireAny evaluation,
/// wildcard satisfaction, role-sourced satisfaction, unknown policies, denial reason text, and
/// argument validation.
/// </summary>
public sealed class GrantAuthorizerPolicyTests
{
    private static GrantAuthorizer Build(
        GrantDiagnostics diagnostics,
        Action<OrionGrantBuilder>? configure = null)
    {
        var builder = new OrionGrantBuilder();
        configure?.Invoke(builder);
        return new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), diagnostics);
    }

    // ---- RequireAll -----------------------------------------------------------------------

    [Fact]
    public void RequireAll_denies_when_a_listed_permission_is_missing()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        var result = authorizer.AuthorizePolicy(principal, "orders.manage");

        Assert.False(result.IsGranted);
        Assert.Contains("orders:write", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void RequireAll_allows_when_every_listed_permission_is_held()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read", "orders:write"] };

        Assert.True(authorizer.AuthorizePolicy(principal, "orders.manage").IsGranted);
    }

    [Fact]
    public void RequireAll_is_satisfied_by_a_single_covering_wildcard()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:*"] };

        Assert.True(authorizer.AuthorizePolicy(principal, "orders.manage").IsGranted);
    }

    [Fact]
    public void RequireAll_can_be_satisfied_through_a_role()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddRole("orders.manager", "orders:*")
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["orders.manager"] };

        Assert.True(authorizer.AuthorizePolicy(principal, "orders.manage").IsGranted);
    }

    // ---- RequireAny -----------------------------------------------------------------------

    [Fact]
    public void RequireAny_allows_when_one_listed_permission_is_held()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:write"] };

        Assert.True(authorizer.AuthorizePolicy(principal, "orders.touch").IsGranted);
    }

    [Fact]
    public void RequireAny_denies_when_none_of_the_listed_permissions_are_held()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["billing:read"] };

        var result = authorizer.AuthorizePolicy(principal, "orders.touch");

        Assert.False(result.IsGranted);
        Assert.Contains("orders.touch", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void RequireAny_single_permission_policy_behaves_like_a_permission_check()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.read", PolicyMode.RequireAny, "orders:read"));

        var allowed = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var denied = new GrantPrincipal { Subject = "u2", Permissions = ["orders:write"] };

        Assert.True(authorizer.AuthorizePolicy(allowed, "orders.read").IsGranted);
        Assert.False(authorizer.AuthorizePolicy(denied, "orders.read").IsGranted);
    }

    // ---- Unknown policy & validation ------------------------------------------------------

    [Fact]
    public void AuthorizePolicy_denies_and_names_an_unknown_policy()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["*"] };

        var result = authorizer.AuthorizePolicy(principal, "missing");

        Assert.False(result.IsGranted);
        Assert.Contains("missing", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthorizePolicy_is_case_sensitive_on_the_policy_name()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.manage", PolicyMode.RequireAny, "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        // "Orders.Manage" is not the registered "orders.manage".
        Assert.False(authorizer.AuthorizePolicy(principal, "Orders.Manage").IsGranted);
    }

    [Fact]
    public void AuthorizePolicy_throws_when_principal_is_null()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);

        Assert.Throws<ArgumentNullException>(() => authorizer.AuthorizePolicy(null!, "orders.manage"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AuthorizePolicy_throws_when_policy_name_is_null_or_empty(string? policyName)
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() => authorizer.AuthorizePolicy(principal, policyName!));
    }
}
