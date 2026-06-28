namespace Moongazing.OrionGrant.AspNetCore;

/// <summary>
/// A resource passed to resource-based authorization that carries the OrionGrant
/// <see cref="ResourceContext"/> describing the object being accessed, plus the
/// <see cref="ResourceAuthorizationOptions"/> governing the ownership and elevation rules. Pass an
/// instance as the resource to <c>IAuthorizationService.AuthorizeAsync(user, resource, requirement)</c>
/// to drive OrionGrant's object-level (IDOR-resistant) check from the framework pipeline.
/// </summary>
/// <remarks>
/// A bare <see cref="ResourceContext"/> may also be passed as the resource; it is treated as this
/// type with default options. Use this wrapper when you need non-default owner comparison or
/// elevated-permission configuration.
/// </remarks>
public sealed class OrionGrantResource
{
    /// <summary>Create a resource descriptor for resource-based authorization.</summary>
    /// <param name="context">The OrionGrant resource context (owner identity and diagnostics).</param>
    /// <param name="options">
    /// The ownership and elevation options, or null for <see cref="ResourceAuthorizationOptions.Default"/>.
    /// </param>
    public OrionGrantResource(ResourceContext context, ResourceAuthorizationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        Context = context;
        Options = options;
    }

    /// <summary>The OrionGrant resource context the object-level check is evaluated against.</summary>
    public ResourceContext Context { get; }

    /// <summary>
    /// The ownership and elevation options, or null to use
    /// <see cref="ResourceAuthorizationOptions.Default"/>.
    /// </summary>
    public ResourceAuthorizationOptions? Options { get; }
}
