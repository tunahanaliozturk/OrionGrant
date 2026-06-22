namespace Moongazing.OrionGrant;

using Moongazing.OrionGrant.Policies;

/// <summary>
/// The structured cause of an authorization denial, attached to a denied
/// <see cref="AuthorizationResult"/> alongside the human-readable
/// <see cref="AuthorizationResult.FailureReason"/>. Lets a caller branch on
/// <see cref="Kind"/> and read the relevant identifiers (which permission, which policy, which
/// mode, owner versus elevated) instead of parsing prose.
/// </summary>
/// <remarks>
/// Which properties are populated depends on <see cref="Kind"/>:
/// <list type="bullet">
/// <item><see cref="DenialKind.MissingPermission"/>: <see cref="Permission"/> names the permission
/// that was not granted.</item>
/// <item><see cref="DenialKind.PolicyNotFound"/>: <see cref="PolicyName"/> names the unknown
/// policy.</item>
/// <item><see cref="DenialKind.PolicyRequirementUnmet"/>: <see cref="PolicyName"/> and
/// <see cref="PolicyMode"/> describe the policy; for a <see cref="Policies.PolicyMode.RequireAll"/>
/// policy <see cref="Permission"/> names the first missing permission.</item>
/// <item><see cref="DenialKind.ResourceOwnership"/>: <see cref="Permission"/> names the held base
/// permission and <see cref="ResourceType"/> / <see cref="ResourceId"/> echo the resource
/// descriptor when supplied.</item>
/// </list>
/// </remarks>
public sealed class DenialReason
{
    private DenialReason(
        DenialKind kind,
        string? permission = null,
        string? policyName = null,
        PolicyMode? policyMode = null,
        string? resourceType = null,
        string? resourceId = null)
    {
        Kind = kind;
        Permission = permission;
        PolicyName = policyName;
        PolicyMode = policyMode;
        ResourceType = resourceType;
        ResourceId = resourceId;
    }

    /// <summary>The category of the denial.</summary>
    public DenialKind Kind { get; }

    /// <summary>
    /// The permission at fault, when one applies: the missing permission for
    /// <see cref="DenialKind.MissingPermission"/>, the first unmet permission of a
    /// <see cref="Policies.PolicyMode.RequireAll"/> policy, or the held base permission for a
    /// <see cref="DenialKind.ResourceOwnership"/> denial. Null otherwise.
    /// </summary>
    public string? Permission { get; }

    /// <summary>
    /// The policy name, for <see cref="DenialKind.PolicyNotFound"/> and
    /// <see cref="DenialKind.PolicyRequirementUnmet"/>. Null otherwise.
    /// </summary>
    public string? PolicyName { get; }

    /// <summary>
    /// The policy mode, for <see cref="DenialKind.PolicyRequirementUnmet"/>. Null otherwise.
    /// </summary>
    public PolicyMode? PolicyMode { get; }

    /// <summary>
    /// The resource type carried for diagnostics on a <see cref="DenialKind.ResourceOwnership"/>
    /// denial, when the caller supplied one on the <see cref="ResourceContext"/>. Null otherwise.
    /// </summary>
    public string? ResourceType { get; }

    /// <summary>
    /// The resource id carried for diagnostics on a <see cref="DenialKind.ResourceOwnership"/>
    /// denial, when the caller supplied one on the <see cref="ResourceContext"/>. Null otherwise.
    /// </summary>
    public string? ResourceId { get; }

    /// <summary>A denial because a required permission was not granted.</summary>
    /// <param name="permission">The permission that was missing.</param>
    public static DenialReason MissingPermission(string permission)
    {
        ArgumentException.ThrowIfNullOrEmpty(permission);
        return new DenialReason(DenialKind.MissingPermission, permission: permission);
    }

    /// <summary>A denial because no policy is registered under the requested name.</summary>
    /// <param name="policyName">The unknown policy name.</param>
    public static DenialReason PolicyNotFound(string policyName)
    {
        ArgumentException.ThrowIfNullOrEmpty(policyName);
        return new DenialReason(DenialKind.PolicyNotFound, policyName: policyName);
    }

    /// <summary>
    /// A denial because a <see cref="Policies.PolicyMode.RequireAll"/> policy was missing a listed
    /// permission.
    /// </summary>
    /// <param name="policyName">The policy that was not satisfied.</param>
    /// <param name="missingPermission">The first listed permission that was not granted.</param>
    public static DenialReason PolicyRequireAllUnmet(string policyName, string missingPermission)
    {
        ArgumentException.ThrowIfNullOrEmpty(policyName);
        ArgumentException.ThrowIfNullOrEmpty(missingPermission);
        return new DenialReason(
            DenialKind.PolicyRequirementUnmet,
            permission: missingPermission,
            policyName: policyName,
            policyMode: Policies.PolicyMode.RequireAll);
    }

    /// <summary>
    /// A denial because a <see cref="Policies.PolicyMode.RequireAny"/> policy was satisfied by none
    /// of its listed permissions.
    /// </summary>
    /// <param name="policyName">The policy that was not satisfied.</param>
    public static DenialReason PolicyRequireAnyUnmet(string policyName)
    {
        ArgumentException.ThrowIfNullOrEmpty(policyName);
        return new DenialReason(
            DenialKind.PolicyRequirementUnmet,
            policyName: policyName,
            policyMode: Policies.PolicyMode.RequireAny);
    }

    /// <summary>
    /// A denial because a resource-aware check passed the base permission gate but the principal
    /// neither owned the resource nor held an elevated grant.
    /// </summary>
    /// <param name="permission">The base permission the principal held.</param>
    /// <param name="resource">The resource descriptor, for diagnostic identifiers.</param>
    public static DenialReason ResourceOwnership(string permission, ResourceContext resource)
    {
        ArgumentException.ThrowIfNullOrEmpty(permission);
        ArgumentNullException.ThrowIfNull(resource);
        return new DenialReason(
            DenialKind.ResourceOwnership,
            permission: permission,
            resourceType: resource.ResourceType,
            resourceId: resource.ResourceId);
    }
}
