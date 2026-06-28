namespace Moongazing.OrionGrant.AspNetCore;

using System.Security.Claims;

using Microsoft.Extensions.Options;

/// <summary>
/// The default <see cref="IGrantPrincipalResolver"/>: builds a <see cref="GrantPrincipal"/> from the
/// claims on a <see cref="ClaimsPrincipal"/>, reading the subject, roles, direct permissions, and
/// explicit denies from the claim types configured by <see cref="OrionGrantClaimsOptions"/>.
/// </summary>
/// <remarks>
/// Returns null for an unauthenticated user or one carrying no subject claim, so the handler denies
/// rather than authorizing an anonymous request. Resolution is synchronous in practice but exposed
/// through the asynchronous <see cref="IGrantPrincipalResolver"/> seam so a custom resolver can
/// consult an external store.
/// </remarks>
public sealed class ClaimsGrantPrincipalResolver : IGrantPrincipalResolver
{
    private const string JwtSubClaimType = "sub";

    private readonly OrionGrantClaimsOptions options;

    /// <summary>Create the resolver with the configured claim types.</summary>
    /// <param name="options">The claim-type configuration.</param>
    public ClaimsGrantPrincipalResolver(IOptions<OrionGrantClaimsOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.options = options.Value;
    }

    /// <inheritdoc />
    public ValueTask<GrantPrincipal?> ResolveAsync(
        ClaimsPrincipal user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (user.Identity is not { IsAuthenticated: true })
        {
            return new ValueTask<GrantPrincipal?>((GrantPrincipal?)null);
        }

        var subject = user.FindFirstValue(options.SubjectClaimType)
            ?? user.FindFirstValue(JwtSubClaimType);

        if (string.IsNullOrEmpty(subject))
        {
            return new ValueTask<GrantPrincipal?>((GrantPrincipal?)null);
        }

        var principal = new GrantPrincipal
        {
            Subject = subject,
            Roles = ValuesOf(user, options.RoleClaimType),
            Permissions = ValuesOf(user, options.PermissionClaimType),
            Denies = ValuesOf(user, options.DenyClaimType),
        };

        return new ValueTask<GrantPrincipal?>(principal);
    }

    private static List<string> ValuesOf(ClaimsPrincipal user, string claimType)
    {
        var values = new List<string>();
        foreach (var claim in user.FindAll(claimType))
        {
            if (!string.IsNullOrEmpty(claim.Value))
            {
                values.Add(claim.Value);
            }
        }

        return values;
    }
}
