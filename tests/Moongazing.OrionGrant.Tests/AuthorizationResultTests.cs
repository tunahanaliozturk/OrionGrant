namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant;

using Xunit;

/// <summary>
/// Coverage of <see cref="AuthorizationResult"/>: the shared granted instance, denied results with
/// reasons, and argument validation on the reason.
/// </summary>
public sealed class AuthorizationResultTests
{
    [Fact]
    public void Granted_is_granted_and_has_no_reason()
    {
        Assert.True(AuthorizationResult.Granted.IsGranted);
        Assert.Null(AuthorizationResult.Granted.FailureReason);
    }

    [Fact]
    public void Granted_is_a_shared_singleton_instance()
    {
        Assert.Same(AuthorizationResult.Granted, AuthorizationResult.Granted);
    }

    [Fact]
    public void Denied_carries_the_reason_and_is_not_granted()
    {
        var result = AuthorizationResult.Denied("nope");

        Assert.False(result.IsGranted);
        Assert.Equal("nope", result.FailureReason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Denied_throws_when_reason_is_null_or_empty(string? reason)
    {
        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() => AuthorizationResult.Denied(reason!));
    }
}
