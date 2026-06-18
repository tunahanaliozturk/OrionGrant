namespace Moongazing.OrionGrant;

/// <summary>
/// Describes the specific resource an authorization decision is made against. The caller supplies
/// the resource's owner identity (for example the user id stored on the row being accessed); the
/// authorizer compares it to the principal's <see cref="GrantPrincipal.Subject"/> to decide
/// object-level (ownership) access.
/// </summary>
/// <remarks>
/// This is the building block for the object-level / IDOR-resistant authorization path: a principal
/// may hold <c>accounts:read</c> yet still only be allowed to read accounts it owns. The optional
/// <see cref="ResourceType"/> and <see cref="ResourceId"/> are not used in the decision; they are
/// carried for logging and diagnostics so a denial can be traced to a concrete resource.
/// </remarks>
public sealed class ResourceContext
{
    /// <summary>
    /// Create a resource context.
    /// </summary>
    /// <param name="ownerId">
    /// The identity that owns the resource, compared against the principal's subject. May be null
    /// or empty for an unowned resource, in which case ownership never matches and access depends
    /// solely on an elevated grant.
    /// </param>
    /// <param name="resourceType">An optional resource type discriminator, for diagnostics only.</param>
    /// <param name="resourceId">An optional resource identifier, for diagnostics only.</param>
    public ResourceContext(string? ownerId, string? resourceType = null, string? resourceId = null)
    {
        OwnerId = ownerId;
        ResourceType = resourceType;
        ResourceId = resourceId;
    }

    /// <summary>
    /// The identity that owns the resource. Compared against <see cref="GrantPrincipal.Subject"/>
    /// to determine ownership. Null or empty means the resource has no owner and ownership can
    /// never be satisfied.
    /// </summary>
    public string? OwnerId { get; }

    /// <summary>An optional resource type discriminator (for example <c>account</c>). Diagnostics only.</summary>
    public string? ResourceType { get; }

    /// <summary>An optional resource identifier. Diagnostics only.</summary>
    public string? ResourceId { get; }

    /// <summary>
    /// Create a context for a resource owned by the given subject. Convenience for the common case
    /// where only the owner identity is known.
    /// </summary>
    /// <param name="ownerId">The owner identity.</param>
    public static ResourceContext OwnedBy(string? ownerId) => new(ownerId);
}
