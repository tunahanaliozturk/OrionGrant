namespace Moongazing.OrionGrant.Tests;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

using Xunit;

public sealed class GrantAuthorizerTests
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
    public void A_direct_permission_grants_access()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        Assert.True(authorizer.Authorize(principal, "orders:read").IsGranted);
        Assert.False(authorizer.Authorize(principal, "orders:write").IsGranted);
    }

    [Fact]
    public void A_role_is_expanded_into_its_permissions()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("orders.manager", "orders:*"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["orders.manager"] };

        Assert.True(authorizer.Authorize(principal, "orders:write").IsGranted);
        Assert.False(authorizer.Authorize(principal, "billing:read").IsGranted);
    }

    [Fact]
    public void An_unknown_role_contributes_nothing()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["ghost"] };

        Assert.False(authorizer.Authorize(principal, "orders:read").IsGranted);
    }

    [Fact]
    public void Effective_permissions_union_roles_and_direct_grants()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("reader", "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"], Permissions = ["billing:read"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Contains("orders:read", effective);
        Assert.Contains("billing:read", effective);
    }

    [Fact]
    public void A_denied_result_carries_a_reason()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        var result = authorizer.Authorize(principal, "orders:read");

        Assert.False(result.IsGranted);
        Assert.Contains("orders:read", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void RequireAll_policy_needs_every_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write"));

        var partial = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var full = new GrantPrincipal { Subject = "u2", Permissions = ["orders:*"] };

        Assert.False(authorizer.AuthorizePolicy(partial, "orders.manage").IsGranted);
        Assert.True(authorizer.AuthorizePolicy(full, "orders.manage").IsGranted);
    }

    [Fact]
    public void RequireAny_policy_needs_one_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b =>
            b.AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));

        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:write"] };

        Assert.True(authorizer.AuthorizePolicy(principal, "orders.touch").IsGranted);
    }

    [Fact]
    public void An_unknown_policy_is_denied()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["*"] };

        var result = authorizer.AuthorizePolicy(principal, "missing");

        Assert.False(result.IsGranted);
        Assert.Contains("missing", result.FailureReason!, StringComparison.Ordinal);
    }
}
