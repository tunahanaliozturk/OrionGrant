namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;

using Xunit;

/// <summary>
/// Coverage of <see cref="GrantAuthorizer.Authorize"/>: allowed and denied single-permission
/// decisions, wildcard grants from roles and direct permissions, the denial reason text, and
/// argument validation.
/// </summary>
public sealed class GrantAuthorizerAuthorizeTests
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
    public void Authorize_allows_a_wildcard_direct_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:*"] };

        Assert.True(authorizer.Authorize(principal, "orders:read").IsGranted);
        Assert.True(authorizer.Authorize(principal, "orders:write:detail").IsGranted);
    }

    [Fact]
    public void Authorize_denies_when_only_a_narrower_permission_is_held()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        Assert.False(authorizer.Authorize(principal, "orders:write").IsGranted);
    }

    [Fact]
    public void Authorize_allows_via_a_root_wildcard_role()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("admin", "*"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["admin"] };

        Assert.True(authorizer.Authorize(principal, "anything:at:all").IsGranted);
    }

    [Fact]
    public void Authorize_denied_result_names_the_missing_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        var result = authorizer.Authorize(principal, "orders:read");

        Assert.False(result.IsGranted);
        Assert.NotNull(result.FailureReason);
        Assert.Contains("orders:read", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Authorize_granted_result_has_no_failure_reason()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        var result = authorizer.Authorize(principal, "orders:read");

        Assert.True(result.IsGranted);
        Assert.Null(result.FailureReason);
    }

    [Fact]
    public void Authorize_throws_when_principal_is_null()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);

        Assert.Throws<ArgumentNullException>(() => authorizer.Authorize(null!, "orders:read"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Authorize_throws_when_required_permission_is_null_or_empty(string? required)
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() => authorizer.Authorize(principal, required!));
    }
}
