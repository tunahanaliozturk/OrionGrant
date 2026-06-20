namespace Moongazing.OrionGrant.Permissions;

/// <summary>
/// Matches a granted permission pattern against a required permission. Permissions are
/// colon-separated hierarchies (for example <c>orders:read</c> or <c>orders:eu:write</c>). A
/// <c>*</c> segment matches one required segment when it is not the last segment, and matches one
/// or more remaining segments when it is the last. So <c>orders:*</c> grants <c>orders:read</c> and
/// <c>orders:read:detail</c> but not the bare <c>orders</c>; <c>*</c> grants everything.
/// </summary>
public static class PermissionMatcher
{
    private const char Separator = ':';
    private const char WildcardChar = '*';

    /// <summary>Does a single granted pattern cover the required permission?</summary>
    /// <param name="pattern">The granted permission pattern.</param>
    /// <param name="required">The permission being checked.</param>
    /// <remarks>
    /// Walks the colon-separated segments of both strings as spans, comparing each segment with
    /// ordinal equality and slicing in place. This allocates nothing: it avoids the two
    /// <c>string.Split(':')</c> arrays the equivalent segment-array implementation would create on
    /// every check, which matters because this runs once per granted pattern on the authorization
    /// hot path. The matching semantics are identical to the array-based form.
    /// </remarks>
    public static bool IsGranted(string pattern, string required)
    {
        ArgumentException.ThrowIfNullOrEmpty(pattern);
        ArgumentException.ThrowIfNullOrEmpty(required);

        return IsGranted(pattern.AsSpan(), required.AsSpan());
    }

    private static bool IsGranted(ReadOnlySpan<char> pattern, ReadOnlySpan<char> required)
    {
        // Two cursors walk the colon-separated segments without allocating. A non-negative cursor
        // points at the start of the next segment; -1 means that side is fully consumed. Because a
        // non-empty string always yields at least one (possibly empty) segment, both cursors start
        // at 0.
        var patternPos = 0;
        var requiredPos = 0;

        while (true)
        {
            var patternSegment = NextSegment(pattern, ref patternPos);
            var isLastPatternSegment = patternPos < 0;
            var isWildcard = patternSegment.Length == 1 && patternSegment[0] == WildcardChar;

            if (isWildcard && isLastPatternSegment)
            {
                // A trailing wildcard covers one or more remaining required segments. That holds iff
                // there is still an unconsumed required segment (mirrors requiredSegments.Length > i
                // in the array-based form, evaluated at the trailing-wildcard pattern index).
                return requiredPos >= 0;
            }

            if (requiredPos < 0)
            {
                // i >= requiredSegments.Length: no required segment remains to line up with this one.
                return false;
            }

            var requiredSegment = NextSegment(required, ref requiredPos);

            if (!isWildcard && !patternSegment.SequenceEqual(requiredSegment))
            {
                return false;
            }

            if (isLastPatternSegment)
            {
                // No trailing wildcard consumed the rest, so the lengths must line up exactly: the
                // required side must also now be fully consumed.
                return requiredPos < 0;
            }
        }
    }

    /// <summary>
    /// Returns the segment of <paramref name="value"/> starting at <paramref name="pos"/> up to the
    /// next <see cref="Separator"/>, then advances <paramref name="pos"/> to the start of the
    /// following segment, or sets it to -1 when the returned segment was the last one.
    /// </summary>
    private static ReadOnlySpan<char> NextSegment(ReadOnlySpan<char> value, ref int pos)
    {
        var remaining = value[pos..];
        var sep = remaining.IndexOf(Separator);
        if (sep < 0)
        {
            pos = -1;
            return remaining;
        }

        pos += sep + 1;
        return remaining[..sep];
    }

    /// <summary>Does any granted pattern in the set cover the required permission?</summary>
    /// <param name="granted">The granted permission patterns.</param>
    /// <param name="required">The permission being checked.</param>
    public static bool IsGrantedByAny(IEnumerable<string> granted, string required)
    {
        ArgumentNullException.ThrowIfNull(granted);
        ArgumentException.ThrowIfNullOrEmpty(required);

        foreach (var pattern in granted)
        {
            if (!string.IsNullOrEmpty(pattern) && IsGranted(pattern, required))
            {
                return true;
            }
        }

        return false;
    }
}
