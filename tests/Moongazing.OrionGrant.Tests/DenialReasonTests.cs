namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of structured denial reasons: every denial path on the authorizer attaches a
/// <see cref="DenialReason"/> whose <see cref="DenialReason.Kind"/> and identifiers match the
/// failure, the human-readable string is preserved for back-compat, and a granted result carries no
/// denial. Also exercises the additive <see cref="AuthorizationResult"/> overloads and the
/// <see cref="DenialReason"/> factory validation directly.
/// </summary>
public sealed class DenialReasonTests
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
    public void Granted_result_has_no_structured_denial()
    {
        Assert.Null(AuthorizationResult.Granted.Denial);
    }

    [Fact]
    public void Back_compat_denied_overload_has_a_reason_but_no_structured_denial()
    {
        var result = AuthorizationResult.Denied("nope");

        Assert.False(result.IsGranted);
        Assert.Equal("nope", result.FailureReason);
        Assert.Null(result.Denial);
    }

    [Fact]
    public void Denied_with_a_structured_cause_carries_both_string_and_denial()
    {
        var denial = DenialReason.MissingPermission("orders:read");
        var result = AuthorizationResult.Denied("Missing permission 'orders:read'.", denial);

        Assert.False(result.IsGranted);
        Assert.Equal("Missing permission 'orders:read'.", result.FailureReason);
        Assert.Same(denial, result.Denial);
    }

    [Fact]
    public void Denied_with_structured_cause_throws_when_denial_is_null()
    {
        Assert.Throws<ArgumentNullException>(() => AuthorizationResult.Denied("reason", null!));
    }

    [Fact]
    public void Missing_permission_denial_names_the_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        var result = authorizer.Authorize(principal, "orders:read");

        Assert.False(result.IsGranted);
        Assert.NotNull(result.Denial);
        Assert.Equal(DenialKind.MissingPermission, result.Denial!.Kind);
        Assert.Equal("orders:read", result.Denial.Permission);
        Assert.Null(result.Denial.PolicyName);
        // The human-readable string is preserved unchanged.
        Assert.Equal("Missing permission 'orders:read'.", result.FailureReason);
    }

    [Fact]
    public void Unknown_policy_denial_is_policy_not_found()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        var result = authorizer.AuthorizePolicy(principal, "ghost.policy");

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.PolicyNotFound, result.Denial!.Kind);
        Assert.Equal("ghost.policy", result.Denial.PolicyName);
        Assert.Null(result.Denial.PolicyMode);
    }

    [Fact]
    public void RequireAll_policy_denial_names_the_first_missing_permission_and_mode()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write"));
        // Holds the first listed permission but not the second.
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        var result = authorizer.AuthorizePolicy(principal, "orders.manage");

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.PolicyRequirementUnmet, result.Denial!.Kind);
        Assert.Equal("orders.manage", result.Denial.PolicyName);
        Assert.Equal(PolicyMode.RequireAll, result.Denial.PolicyMode);
        Assert.Equal("orders:write", result.Denial.Permission);
    }

    [Fact]
    public void RequireAny_policy_denial_reports_the_mode_and_no_single_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["billing:read"] };

        var result = authorizer.AuthorizePolicy(principal, "orders.touch");

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.PolicyRequirementUnmet, result.Denial!.Kind);
        Assert.Equal("orders.touch", result.Denial.PolicyName);
        Assert.Equal(PolicyMode.RequireAny, result.Denial.PolicyMode);
        // RequireAny has no single culprit permission.
        Assert.Null(result.Denial.Permission);
    }

    [Fact]
    public void Resource_missing_base_permission_is_missing_permission_not_ownership()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };
        var resource = ResourceContext.OwnedBy("u1");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.MissingPermission, result.Denial!.Kind);
        Assert.Equal("accounts:read", result.Denial.Permission);
    }

    [Fact]
    public void Resource_ownership_denial_carries_kind_permission_and_resource_descriptor()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };
        var resource = new ResourceContext(ownerId: "u2", resourceType: "account", resourceId: "42");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ResourceOwnership, result.Denial!.Kind);
        Assert.Equal("accounts:read", result.Denial.Permission);
        Assert.Equal("account", result.Denial.ResourceType);
        Assert.Equal("42", result.Denial.ResourceId);
    }

    [Fact]
    public void Resource_ownership_denial_via_interface_default_method_is_structured()
    {
        // Exercise the IGrantAuthorizer default interface method, not the GrantAuthorizer override,
        // by calling through a minimal custom implementor.
        IGrantAuthorizer authorizer = new PermissionOnlyAuthorizer("accounts:read");
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };
        var resource = new ResourceContext(ownerId: "u2", resourceType: "account", resourceId: "7");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ResourceOwnership, result.Denial!.Kind);
        Assert.Equal("accounts:read", result.Denial.Permission);
        Assert.Equal("7", result.Denial.ResourceId);
    }

    [Fact]
    public void MissingPermission_factory_validates_its_argument()
    {
        Assert.ThrowsAny<ArgumentException>(() => DenialReason.MissingPermission(""));
        Assert.ThrowsAny<ArgumentException>(() => DenialReason.MissingPermission(null!));
    }

    [Fact]
    public void ResourceOwnership_factory_validates_its_arguments()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => DenialReason.ResourceOwnership("", ResourceContext.OwnedBy("u1")));
        Assert.Throws<ArgumentNullException>(
            () => DenialReason.ResourceOwnership("accounts:read", null!));
    }

    /// <summary>
    /// A minimal <see cref="IGrantAuthorizer"/> that grants exactly one permission and defines no
    /// roles or policies. It implements only the abstract members, so the resource-aware overload
    /// and the batch methods resolve to their default interface implementations.
    /// </summary>
    private sealed class PermissionOnlyAuthorizer(string heldPermission) : IGrantAuthorizer
    {
        public AuthorizationResult Authorize(GrantPrincipal principal, string requiredPermission) =>
            string.Equals(requiredPermission, heldPermission, StringComparison.Ordinal)
                ? AuthorizationResult.Granted
                : AuthorizationResult.Denied(
                    $"Missing permission '{requiredPermission}'.",
                    DenialReason.MissingPermission(requiredPermission));

        public AuthorizationResult AuthorizePolicy(GrantPrincipal principal, string policyName) =>
            AuthorizationResult.Denied(
                $"Unknown policy '{policyName}'.",
                DenialReason.PolicyNotFound(policyName));

        public IReadOnlySet<string> EffectivePermissions(GrantPrincipal principal) =>
            new HashSet<string>(StringComparer.Ordinal) { heldPermission };
    }
}
