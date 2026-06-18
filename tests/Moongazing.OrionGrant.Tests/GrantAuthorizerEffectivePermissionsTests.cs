namespace Moongazing.OrionGrant.Tests;

using System;
using System.Linq;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;

using Xunit;

/// <summary>
/// Coverage of <see cref="GrantAuthorizer.EffectivePermissions"/>: additive role expansion,
/// unioning direct grants with role grants, unknown-role handling, multiple roles, deduplication,
/// empty sets, and argument validation.
/// </summary>
public sealed class GrantAuthorizerEffectivePermissionsTests
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
    public void Effective_permissions_of_a_bare_principal_are_empty()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.Empty(authorizer.EffectivePermissions(principal));
    }

    [Fact]
    public void Effective_permissions_include_direct_grants_only_when_no_roles()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read", "billing:read"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Equal(2, effective.Count);
        Assert.Contains("orders:read", effective);
        Assert.Contains("billing:read", effective);
    }

    [Fact]
    public void Effective_permissions_expand_multiple_roles_additively()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddRole("reader", "orders:read")
            .AddRole("biller", "billing:read", "billing:write"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader", "biller"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Equal(3, effective.Count);
        Assert.Contains("orders:read", effective);
        Assert.Contains("billing:read", effective);
        Assert.Contains("billing:write", effective);
    }

    [Fact]
    public void Effective_permissions_deduplicate_overlap_between_role_and_direct_grant()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("reader", "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"], Permissions = ["orders:read"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Single(effective);
        Assert.Contains("orders:read", effective);
    }

    [Fact]
    public void Effective_permissions_ignore_an_unknown_role()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("reader", "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader", "ghost"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Single(effective);
        Assert.Contains("orders:read", effective);
    }

    [Fact]
    public void Effective_permissions_skip_an_empty_role_name()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("reader", "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["", "reader"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Single(effective);
        Assert.Contains("orders:read", effective);
    }

    [Fact]
    public void Effective_permissions_are_case_sensitive_for_role_names()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("Reader", "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"] };

        // "reader" != "Reader" under the Ordinal comparer the registry is built with.
        Assert.Empty(authorizer.EffectivePermissions(principal));
    }

    [Fact]
    public void Adding_a_role_twice_unions_its_permission_sets()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddRole("reader", "orders:read")
            .AddRole("reader", "billing:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Equal(2, effective.Count);
        Assert.Contains("orders:read", effective);
        Assert.Contains("billing:read", effective);
    }

    [Fact]
    public void Effective_permissions_throw_when_principal_is_null()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);

        Assert.Throws<ArgumentNullException>(() => authorizer.EffectivePermissions(null!));
    }
}
