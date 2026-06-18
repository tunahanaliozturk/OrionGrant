namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of <see cref="GrantAuthorizer"/> constructor argument validation.
/// </summary>
public sealed class GrantAuthorizerConstructionTests
{
    [Fact]
    public void Constructor_throws_when_roles_is_null()
    {
        using var diag = new GrantDiagnostics();
        Assert.Throws<ArgumentNullException>(
            () => new GrantAuthorizer(null!, PolicyRegistry.Empty, diag));
    }

    [Fact]
    public void Constructor_throws_when_policies_is_null()
    {
        using var diag = new GrantDiagnostics();
        Assert.Throws<ArgumentNullException>(
            () => new GrantAuthorizer(RoleRegistry.Empty, null!, diag));
    }

    [Fact]
    public void Constructor_throws_when_diagnostics_is_null()
    {
        Assert.Throws<ArgumentNullException>(
            () => new GrantAuthorizer(RoleRegistry.Empty, PolicyRegistry.Empty, null!));
    }

    [Fact]
    public void Empty_registries_yield_an_authorizer_that_denies_everything()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = new GrantAuthorizer(RoleRegistry.Empty, PolicyRegistry.Empty, diag);
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["anything"] };

        Assert.False(authorizer.Authorize(principal, "orders:read").IsGranted);
        Assert.False(authorizer.AuthorizePolicy(principal, "anything").IsGranted);
    }
}
