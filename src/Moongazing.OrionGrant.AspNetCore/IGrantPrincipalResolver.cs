namespace Moongazing.OrionGrant.AspNetCore;

using System.Security.Claims;

/// <summary>
/// Resolves the OrionGrant <see cref="GrantPrincipal"/> for the current
/// <see cref="ClaimsPrincipal"/> so the authorization handler can run an OrionGrant check against
/// it. OrionGrant decides "is this principal allowed"; this seam answers "what does this principal
/// hold", reading the subject, roles, direct permissions, and explicit denies from wherever the
/// application keeps them (claims, a cache, a store).
/// </summary>
/// <remarks>
/// The default <see cref="ClaimsGrantPrincipalResolver"/> reads them from claims. Register your own
/// implementation to source grants from elsewhere; resolution is allowed to be asynchronous so a
/// resolver may consult an external store.
/// </remarks>
public interface IGrantPrincipalResolver
{
    /// <summary>
    /// Resolve the OrionGrant principal for <paramref name="user"/>, or null when no principal can
    /// be resolved (for example an unauthenticated request), in which case the check is denied.
    /// </summary>
    /// <param name="user">The authenticated user the framework is evaluating.</param>
    /// <param name="cancellationToken">Cancels the resolution.</param>
    ValueTask<GrantPrincipal?> ResolveAsync(
        ClaimsPrincipal user,
        CancellationToken cancellationToken = default);
}
