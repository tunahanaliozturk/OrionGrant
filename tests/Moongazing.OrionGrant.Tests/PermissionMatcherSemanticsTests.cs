namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant.Permissions;

using Xunit;

/// <summary>
/// Exhaustive coverage of <see cref="PermissionMatcher"/> wildcard semantics: exact matches,
/// trailing wildcards, segment wildcards, the root wildcard, same-length mismatches, case
/// sensitivity, malformed patterns, and argument validation. Every assertion documents the
/// matcher's real, current behavior.
/// </summary>
public sealed class PermissionMatcherSemanticsTests
{
    // ---- Exact matches --------------------------------------------------------------------

    [Theory]
    [InlineData("orders", "orders")]
    [InlineData("orders:read", "orders:read")]
    [InlineData("orders:eu:write", "orders:eu:write")]
    public void IsGranted_exact_pattern_matches_identical_required(string pattern, string required)
    {
        Assert.True(PermissionMatcher.IsGranted(pattern, required));
    }

    [Theory]
    [InlineData("orders:read", "orders:write")]
    [InlineData("orders:read", "billing:read")]
    [InlineData("orders:eu:read", "orders:us:read")]
    public void IsGranted_exact_pattern_rejects_a_different_required(string pattern, string required)
    {
        Assert.False(PermissionMatcher.IsGranted(pattern, required));
    }

    // ---- Same-length mismatch (no wildcard to bridge) -------------------------------------

    [Fact]
    public void IsGranted_same_length_but_segment_differs_is_false()
    {
        Assert.False(PermissionMatcher.IsGranted("orders:read", "orders:list"));
    }

    [Theory]
    [InlineData("orders:read", "orders:read:detail")] // pattern shorter, no trailing wildcard
    [InlineData("orders:read:detail", "orders:read")] // pattern longer
    [InlineData("orders", "orders:read")]
    public void IsGranted_length_mismatch_without_wildcard_is_false(string pattern, string required)
    {
        Assert.False(PermissionMatcher.IsGranted(pattern, required));
    }

    // ---- Trailing wildcard ----------------------------------------------------------------

    [Theory]
    [InlineData("orders:*", "orders:read")]
    [InlineData("orders:*", "orders:write")]
    [InlineData("orders:*", "orders:read:detail")] // covers one or more remaining segments
    [InlineData("orders:eu:*", "orders:eu:read")]
    public void IsGranted_trailing_wildcard_covers_one_or_more_remaining_segments(string pattern, string required)
    {
        Assert.True(PermissionMatcher.IsGranted(pattern, required));
    }

    [Theory]
    [InlineData("orders:*", "orders")]       // trailing wildcard needs at least one more segment
    [InlineData("orders:eu:*", "orders:eu")] // same: nothing left for the wildcard to consume
    [InlineData("orders:*", "billing:read")] // prefix literal must still match
    public void IsGranted_trailing_wildcard_requires_a_remaining_segment_and_matching_prefix(
        string pattern,
        string required)
    {
        Assert.False(PermissionMatcher.IsGranted(pattern, required));
    }

    // ---- Root wildcard --------------------------------------------------------------------

    [Theory]
    [InlineData("*", "orders")]
    [InlineData("*", "orders:read")]
    [InlineData("*", "orders:eu:write:detail")]
    [InlineData("*", "anything")]
    public void IsGranted_root_wildcard_covers_everything_with_at_least_one_segment(string pattern, string required)
    {
        Assert.True(PermissionMatcher.IsGranted(pattern, required));
    }

    // ---- Segment (non-trailing) wildcard --------------------------------------------------

    [Theory]
    [InlineData("orders:*:read", "orders:eu:read")]
    [InlineData("orders:*:read", "orders:us:read")]
    [InlineData("*:read", "orders:read")]   // leading wildcard segment
    [InlineData("*:*:read", "orders:eu:read")]
    public void IsGranted_segment_wildcard_matches_exactly_one_segment(string pattern, string required)
    {
        Assert.True(PermissionMatcher.IsGranted(pattern, required));
    }

    [Theory]
    [InlineData("orders:*:read", "orders:eu:write")]    // tail literal differs
    [InlineData("orders:*:read", "orders:eu:fr:read")]  // segment wildcard does not span two segments
    [InlineData("orders:*:read", "orders:read")]        // required too short for the middle segment
    public void IsGranted_segment_wildcard_does_not_span_or_bridge(string pattern, string required)
    {
        Assert.False(PermissionMatcher.IsGranted(pattern, required));
    }

    // ---- Case sensitivity (Ordinal) -------------------------------------------------------

    [Theory]
    [InlineData("Orders:read", "orders:read")]
    [InlineData("orders:Read", "orders:read")]
    [InlineData("orders:read", "Orders:read")]
    public void IsGranted_is_case_sensitive_ordinal(string pattern, string required)
    {
        Assert.False(PermissionMatcher.IsGranted(pattern, required));
    }

    // ---- Malformed / empty-segment patterns -----------------------------------------------

    [Fact]
    public void IsGranted_empty_middle_segments_compare_literally()
    {
        // "orders::read" -> ["orders", "", "read"]; an empty segment only matches another empty one.
        Assert.True(PermissionMatcher.IsGranted("orders::read", "orders::read"));
        Assert.False(PermissionMatcher.IsGranted("orders::read", "orders:eu:read"));
    }

    [Fact]
    public void IsGranted_trailing_separator_creates_a_trailing_empty_segment()
    {
        // "orders:" -> ["orders", ""]; the empty last segment is a literal, not a wildcard.
        Assert.False(PermissionMatcher.IsGranted("orders:", "orders"));
        Assert.True(PermissionMatcher.IsGranted("orders:", "orders:"));
    }

    [Fact]
    public void IsGranted_literal_asterisk_inside_a_segment_is_not_a_wildcard()
    {
        // Only a segment equal to exactly "*" is a wildcard; "ord*" is a literal segment.
        Assert.False(PermissionMatcher.IsGranted("ord*", "orders"));
        Assert.True(PermissionMatcher.IsGranted("ord*", "ord*"));
    }

    // ---- Argument validation --------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsGranted_throws_when_pattern_is_null_or_empty(string? pattern)
    {
        // ThrowIfNullOrEmpty throws ArgumentNullException for null and ArgumentException for empty;
        // both derive from ArgumentException, so assert the base type.
        Assert.ThrowsAny<ArgumentException>(() => PermissionMatcher.IsGranted(pattern!, "orders:read"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsGranted_throws_when_required_is_null_or_empty(string? required)
    {
        Assert.ThrowsAny<ArgumentException>(() => PermissionMatcher.IsGranted("orders:read", required!));
    }
}
