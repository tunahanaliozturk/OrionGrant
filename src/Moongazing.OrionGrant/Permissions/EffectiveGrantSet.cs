namespace Moongazing.OrionGrant.Permissions;

/// <summary>
/// A principal's resolved authorization set after role and inclusion expansion: the permission
/// patterns the principal is granted (<see cref="Allows"/>) and the patterns explicitly denied to
/// it (<see cref="Denies"/>). Denies override allows (deny-overrides precedence), so a required
/// permission is authorized only when some allow covers it and no deny covers it.
/// </summary>
/// <remarks>
/// This is the value the effective-set cache stores per principal. It is immutable once built. The
/// allow set is the union of the principal's direct permissions and every role's (transitively
/// expanded) permissions, exactly as <see cref="Moongazing.OrionGrant.IGrantAuthorizer.EffectivePermissions"/>
/// returns; the deny set is the principal's explicit denies. A principal with no explicit denies has
/// an empty <see cref="Denies"/> and behaves exactly as in 0.3.0.
/// </remarks>
public sealed class EffectiveGrantSet
{
    private static readonly IReadOnlySet<string> Empty =
        new HashSet<string>(StringComparer.Ordinal);

    /// <summary>Create an effective grant set from an allow set and a deny set.</summary>
    /// <param name="allows">The granted permission patterns (direct plus role-expanded).</param>
    /// <param name="denies">The explicitly denied permission patterns. Null is treated as empty.</param>
    public EffectiveGrantSet(IReadOnlySet<string> allows, IReadOnlySet<string>? denies = null)
    {
        ArgumentNullException.ThrowIfNull(allows);
        Allows = allows;
        Denies = denies ?? Empty;
    }

    /// <summary>The granted permission patterns: direct grants unioned with role-expanded grants.</summary>
    public IReadOnlySet<string> Allows { get; }

    /// <summary>
    /// The explicitly denied permission patterns. A deny that covers a required permission overrides
    /// any allow that also covers it (deny-overrides). Empty when the principal declares no denies.
    /// </summary>
    public IReadOnlySet<string> Denies { get; }

    /// <summary>True when the principal declares at least one explicit deny.</summary>
    public bool HasDenies => Denies.Count > 0;

    /// <summary>
    /// Find the deny pattern, if any, that covers <paramref name="required"/>. Returns the matching
    /// deny pattern so a denial reason can name the carve-out that blocked the request, or null when
    /// no deny covers the requirement.
    /// </summary>
    /// <param name="required">The permission being checked.</param>
    public string? MatchingDeny(string required)
    {
        ArgumentException.ThrowIfNullOrEmpty(required);
        if (Denies.Count == 0)
        {
            return null;
        }

        foreach (var pattern in Denies)
        {
            if (!string.IsNullOrEmpty(pattern) && PermissionMatcher.IsGranted(pattern, required))
            {
                return pattern;
            }
        }

        return null;
    }
}
