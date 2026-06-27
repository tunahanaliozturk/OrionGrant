namespace Moongazing.OrionGrant.Permissions;

/// <summary>
/// Caches a principal's resolved <see cref="EffectiveGrantSet"/> (its allow union after role and
/// inclusion expansion, plus its explicit denies) so a call site that authorizes the same principal
/// many times in one request does not re-expand the set on every check.
/// </summary>
/// <remarks>
/// <para>
/// The cache is keyed on the principal's roles, direct permissions, and denies, not on its
/// <see cref="GrantPrincipal.Subject"/>. Two principals with the same roles, grants, and denies
/// share a cache entry; a principal whose role, grant, or deny membership changes computes a
/// different key and therefore never serves a stale entry. This makes the only correctness-relevant
/// staleness vector part of the key by construction.
/// </para>
/// <para>
/// Role <em>contents</em> are fixed: the <see cref="RoleRegistry"/> is immutable and built once, so
/// a cache is scoped to a single authorizer/registry pair and cannot serve an entry resolved against
/// a different registry. Rebuilding the registry produces a new authorizer with its own cache. If a
/// host mutates role definitions at runtime by some other means, it must dispose or replace the
/// authorizer; the cache deliberately does not attempt to observe registry changes.
/// </para>
/// </remarks>
public interface IEffectiveGrantCache
{
    /// <summary>
    /// Return the cached effective grant set for <paramref name="principal"/>, computing and storing
    /// it via <paramref name="factory"/> on a miss.
    /// </summary>
    /// <param name="principal">The principal whose effective set is wanted.</param>
    /// <param name="factory">Builds the set on a cache miss. Invoked at most once per miss.</param>
    EffectiveGrantSet GetOrAdd(GrantPrincipal principal, Func<GrantPrincipal, EffectiveGrantSet> factory);
}
