namespace Moongazing.OrionGrant.Tests;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;

using Xunit;

/// <summary>
/// Coverage of <see cref="ResourceContext"/> construction and the resource-aware default interface
/// method on <see cref="IGrantAuthorizer"/>, ensuring the contract behaves identically whether
/// callers reach it through the interface or the concrete type.
/// </summary>
public sealed class ResourceContextTests
{
    [Fact]
    public void OwnedBy_sets_only_the_owner_id()
    {
        var resource = ResourceContext.OwnedBy("u1");

        Assert.Equal("u1", resource.OwnerId);
        Assert.Null(resource.ResourceType);
        Assert.Null(resource.ResourceId);
    }

    [Fact]
    public void Constructor_carries_type_and_id_for_diagnostics()
    {
        var resource = new ResourceContext("u1", "account", "acc-42");

        Assert.Equal("u1", resource.OwnerId);
        Assert.Equal("account", resource.ResourceType);
        Assert.Equal("acc-42", resource.ResourceId);
    }

    [Fact]
    public void Default_options_expose_ordinal_comparison_and_no_elevated_permissions()
    {
        Assert.Equal(System.StringComparison.Ordinal, ResourceAuthorizationOptions.Default.OwnerComparison);
        Assert.Empty(ResourceAuthorizationOptions.Default.ElevatedPermissions);
        Assert.True(ResourceAuthorizationOptions.Default.TreatRootWildcardAsElevated);
    }

    [Fact]
    public void Interface_default_method_denies_non_owner_holding_the_permission()
    {
        using var diag = new GrantDiagnostics();
        IGrantAuthorizer authorizer = new GrantAuthorizer(
            new OrionGrantBuilder().BuildRoles(),
            new OrionGrantBuilder().BuildPolicies(),
            diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };

        var result = authorizer.Authorize(principal, "accounts:read", ResourceContext.OwnedBy("u2"));

        Assert.False(result.IsGranted);
    }

    [Fact]
    public void Interface_default_method_allows_owner()
    {
        using var diag = new GrantDiagnostics();
        IGrantAuthorizer authorizer = new GrantAuthorizer(
            new OrionGrantBuilder().BuildRoles(),
            new OrionGrantBuilder().BuildPolicies(),
            diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };

        var result = authorizer.Authorize(principal, "accounts:read", ResourceContext.OwnedBy("u1"));

        Assert.True(result.IsGranted);
    }
}
