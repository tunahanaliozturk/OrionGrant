namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;

using Xunit;

/// <summary>
/// Coverage of the resource-aware (object-level / ownership) authorization path
/// <see cref="GrantAuthorizer.Authorize(GrantPrincipal, string, ResourceContext, ResourceAuthorizationOptions?)"/>:
/// owner allowed, non-owner denied despite holding the permission (the IDOR case), elevated/admin
/// bypass, missing permission denied regardless of ownership, and argument validation.
/// </summary>
public sealed class GrantAuthorizerResourceTests
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
    public void Owner_holding_the_permission_is_allowed_for_its_own_resource()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };
        var resource = ResourceContext.OwnedBy("u1");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.True(result.IsGranted);
        Assert.Null(result.FailureReason);
    }

    [Fact]
    public void Non_owner_is_denied_even_when_holding_the_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };
        var resource = ResourceContext.OwnedBy("u2");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
        Assert.NotNull(result.FailureReason);
        Assert.Contains("not the owner", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Root_wildcard_admin_bypasses_ownership()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("admin", "*"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["admin"] };
        var resource = ResourceContext.OwnedBy("someone-else");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.True(result.IsGranted);
    }

    [Fact]
    public void Configured_elevated_permission_bypasses_ownership()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "support-agent",
            Permissions = ["accounts:read", "accounts:read:any"],
        };
        var resource = ResourceContext.OwnedBy("some-customer");
        var options = new ResourceAuthorizationOptions
        {
            ElevatedPermissions = ["accounts:read:any"],
        };

        var result = authorizer.Authorize(principal, "accounts:read", resource, options);

        Assert.True(result.IsGranted);
    }

    [Fact]
    public void Owner_without_the_permission_is_denied()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };
        var resource = ResourceContext.OwnedBy("u1");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
        Assert.NotNull(result.FailureReason);
        Assert.Contains("accounts:read", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_permission_is_denied_even_for_the_owner_with_an_elevated_grant_elsewhere()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        // Holds an unrelated elevated permission but not the base permission being checked.
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["billing:*"] };
        var resource = ResourceContext.OwnedBy("u1");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
        Assert.Contains("Missing permission", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Unowned_resource_is_denied_for_a_non_elevated_principal()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };
        var resource = ResourceContext.OwnedBy(null);

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
    }

    [Fact]
    public void Root_wildcard_does_not_bypass_when_disabled()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("admin", "*"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["admin"] };
        var resource = ResourceContext.OwnedBy("someone-else");
        var options = new ResourceAuthorizationOptions { TreatRootWildcardAsElevated = false };

        // The base permission still passes via the root grant, but ownership now governs and fails.
        var result = authorizer.Authorize(principal, "accounts:read", resource, options);

        Assert.False(result.IsGranted);
        Assert.Contains("not the owner", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Owner_comparison_can_be_made_case_insensitive()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "User1", Permissions = ["accounts:read"] };
        var resource = ResourceContext.OwnedBy("user1");
        var options = new ResourceAuthorizationOptions
        {
            OwnerComparison = StringComparison.OrdinalIgnoreCase,
        };

        Assert.True(authorizer.Authorize(principal, "accounts:read", resource, options).IsGranted);
        // And without the override, the default ordinal comparison denies the mismatch.
        Assert.False(authorizer.Authorize(principal, "accounts:read", resource).IsGranted);
    }

    [Fact]
    public void Authorize_throws_when_principal_is_null()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);

        Assert.Throws<ArgumentNullException>(() =>
            authorizer.Authorize(null!, "accounts:read", ResourceContext.OwnedBy("u1")));
    }

    [Fact]
    public void Authorize_throws_when_resource_is_null()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.Throws<ArgumentNullException>(() =>
            authorizer.Authorize(principal, "accounts:read", null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Authorize_throws_when_required_permission_is_null_or_empty(string? required)
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.ThrowsAny<ArgumentException>(() =>
            authorizer.Authorize(principal, required!, ResourceContext.OwnedBy("u1")));
    }
}
