namespace Moongazing.OrionGrant.Tests;

using Moongazing.OrionGrant.Permissions;

using Xunit;

public sealed class PermissionMatcherTests
{
    [Theory]
    [InlineData("orders:read", "orders:read", true)]
    [InlineData("orders:read", "orders:write", false)]
    [InlineData("orders:*", "orders:read", true)]
    [InlineData("orders:*", "orders:read:detail", true)]
    [InlineData("orders:*", "orders", false)]
    [InlineData("*", "orders:read", true)]
    [InlineData("*", "anything", true)]
    [InlineData("orders:*:read", "orders:eu:read", true)]
    [InlineData("orders:*:read", "orders:eu:write", false)]
    [InlineData("orders:read", "orders:read:detail", false)]
    [InlineData("orders:read:detail", "orders:read", false)]
    [InlineData("orders", "orders", true)]
    public void IsGranted_matches_the_specification(string pattern, string required, bool expected)
    {
        Assert.Equal(expected, PermissionMatcher.IsGranted(pattern, required));
    }

    [Fact]
    public void IsGrantedByAny_is_true_when_any_pattern_matches()
    {
        string[] granted = ["billing:read", "orders:*"];
        Assert.True(PermissionMatcher.IsGrantedByAny(granted, "orders:write"));
        Assert.False(PermissionMatcher.IsGrantedByAny(granted, "users:read"));
    }

    [Fact]
    public void IsGrantedByAny_skips_empty_patterns()
    {
        string[] granted = ["", "orders:read"];
        Assert.True(PermissionMatcher.IsGrantedByAny(granted, "orders:read"));
    }
}
