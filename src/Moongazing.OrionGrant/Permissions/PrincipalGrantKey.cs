namespace Moongazing.OrionGrant.Permissions;

using System.Text;

/// <summary>
/// A deterministic, value-based cache key for a principal's effective grant set, derived from the
/// principal's roles, direct permissions, and explicit denies. The subject is deliberately excluded:
/// the effective set depends only on what the principal holds, not on who it is, so two principals
/// with identical roles, grants, and denies share an entry. Membership is order-independent (the
/// three collections are sorted before hashing) so the same logical principal yields the same key
/// regardless of the order its collections were populated in.
/// </summary>
internal readonly struct PrincipalGrantKey : IEquatable<PrincipalGrantKey>
{
    // Control characters chosen because they cannot appear in a normal permission/role string, so
    // distinct memberships can never produce the same composite key by accident.
    private const char SectionSeparator = '\u001E'; // record separator, between roles/perms/denies
    private const char EntrySeparator = '\u001F';   // unit separator, between entries in a section

    private readonly string composite;
    private readonly int hash;

    private PrincipalGrantKey(string composite)
    {
        this.composite = composite;
        hash = string.GetHashCode(composite, StringComparison.Ordinal);
    }

    /// <summary>Build a key from a principal's role, permission, and deny membership.</summary>
    /// <param name="principal">The principal to key on.</param>
    public static PrincipalGrantKey For(GrantPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var builder = new StringBuilder();
        Append(builder, principal.Roles);
        builder.Append(SectionSeparator);
        Append(builder, principal.Permissions);
        builder.Append(SectionSeparator);
        Append(builder, principal.Denies);

        return new PrincipalGrantKey(builder.ToString());
    }

    private static void Append(StringBuilder builder, IReadOnlyCollection<string> values)
    {
        if (values.Count == 0)
        {
            return;
        }

        // Sort a snapshot so the key is independent of the caller's collection order, and use a unit
        // separator between entries so {"a","bc"} and {"ab","c"} never collide.
        var sorted = new string[values.Count];
        var i = 0;
        foreach (var value in values)
        {
            sorted[i++] = value ?? string.Empty;
        }

        Array.Sort(sorted, StringComparer.Ordinal);
        for (var j = 0; j < sorted.Length; j++)
        {
            if (j > 0)
            {
                builder.Append(EntrySeparator);
            }

            builder.Append(sorted[j]);
        }
    }

    /// <inheritdoc />
    public bool Equals(PrincipalGrantKey other) =>
        string.Equals(composite, other.composite, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PrincipalGrantKey other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => hash;
}
