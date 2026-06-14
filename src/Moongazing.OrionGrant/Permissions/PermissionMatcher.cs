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
    private const string Wildcard = "*";

    /// <summary>Does a single granted pattern cover the required permission?</summary>
    /// <param name="pattern">The granted permission pattern.</param>
    /// <param name="required">The permission being checked.</param>
    public static bool IsGranted(string pattern, string required)
    {
        ArgumentException.ThrowIfNullOrEmpty(pattern);
        ArgumentException.ThrowIfNullOrEmpty(required);

        var patternSegments = pattern.Split(Separator);
        var requiredSegments = required.Split(Separator);

        for (var i = 0; i < patternSegments.Length; i++)
        {
            var segment = patternSegments[i];
            var isLast = i == patternSegments.Length - 1;

            if (segment == Wildcard && isLast)
            {
                // A trailing wildcard covers one or more remaining required segments.
                return requiredSegments.Length > i;
            }

            if (i >= requiredSegments.Length)
            {
                return false;
            }

            if (segment != Wildcard && !string.Equals(segment, requiredSegments[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        // No trailing wildcard consumed the rest, so the lengths must line up exactly.
        return patternSegments.Length == requiredSegments.Length;
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
