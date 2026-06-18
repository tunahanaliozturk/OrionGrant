namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant.Permissions;

using Xunit;

/// <summary>
/// Coverage of <see cref="PermissionMatcher.IsGrantedByAny"/>: the OR over a granted set, the
/// short-circuit on the first match, empty-set and empty-pattern handling, and argument validation.
/// </summary>
public sealed class PermissionMatcherIsGrantedByAnyTests
{
    [Fact]
    public void IsGrantedByAny_true_when_a_later_pattern_matches()
    {
        string[] granted = ["billing:read", "users:*", "orders:*"];
        Assert.True(PermissionMatcher.IsGrantedByAny(granted, "orders:write"));
    }

    [Fact]
    public void IsGrantedByAny_false_when_no_pattern_matches()
    {
        string[] granted = ["billing:read", "orders:read"];
        Assert.False(PermissionMatcher.IsGrantedByAny(granted, "users:read"));
    }

    [Fact]
    public void IsGrantedByAny_over_an_empty_set_is_false()
    {
        Assert.False(PermissionMatcher.IsGrantedByAny([], "orders:read"));
    }

    [Fact]
    public void IsGrantedByAny_skips_null_and_empty_patterns()
    {
        string?[] granted = [null, "", "orders:read"];
        Assert.True(PermissionMatcher.IsGrantedByAny(granted!, "orders:read"));
    }

    [Fact]
    public void IsGrantedByAny_with_only_empty_patterns_is_false()
    {
        string[] granted = ["", ""];
        Assert.False(PermissionMatcher.IsGrantedByAny(granted, "orders:read"));
    }

    [Fact]
    public void IsGrantedByAny_root_wildcard_grants_any_required()
    {
        string[] granted = ["*"];
        Assert.True(PermissionMatcher.IsGrantedByAny(granted, "orders:eu:write:detail"));
        Assert.True(PermissionMatcher.IsGrantedByAny(granted, "anything"));
    }

    [Fact]
    public void IsGrantedByAny_is_case_sensitive()
    {
        string[] granted = ["Orders:read"];
        Assert.False(PermissionMatcher.IsGrantedByAny(granted, "orders:read"));
    }

    [Fact]
    public void IsGrantedByAny_throws_when_granted_is_null()
    {
        Assert.Throws<ArgumentNullException>(() => PermissionMatcher.IsGrantedByAny(null!, "orders:read"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsGrantedByAny_throws_when_required_is_null_or_empty(string? required)
    {
        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() => PermissionMatcher.IsGrantedByAny(["orders:read"], required!));
    }
}
