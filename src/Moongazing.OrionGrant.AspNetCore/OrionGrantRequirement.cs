namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.AspNetCore.Authorization;

/// <summary>
/// An ASP.NET Core authorization requirement backed by an OrionGrant check: either a single
/// permission or a named OrionGrant policy. The <see cref="OrionGrantAuthorizationHandler"/>
/// resolves the current principal's grants and runs the corresponding OrionGrant check, supplying
/// the structured denial reason to the framework on failure.
/// </summary>
/// <remarks>
/// When the authorization call carries a resource (resource-based authorization via
/// <c>IAuthorizationService.AuthorizeAsync(user, resource, requirement)</c>), the handler applies
/// OrionGrant's object-level / ownership-aware check to a <see cref="OrionGrantResource"/> or a
/// <see cref="ResourceContext"/> resource. A permission requirement with no resource is a plain
/// permission check.
/// </remarks>
public sealed class OrionGrantRequirement : IAuthorizationRequirement
{
    private OrionGrantRequirement(OrionGrantRequirementKind kind, string value)
    {
        Kind = kind;
        Value = value;
    }

    /// <summary>Whether this requirement evaluates a permission or a named policy.</summary>
    public OrionGrantRequirementKind Kind { get; }

    /// <summary>
    /// The permission string (for <see cref="OrionGrantRequirementKind.Permission"/>) or the policy
    /// name (for <see cref="OrionGrantRequirementKind.Policy"/>) being required.
    /// </summary>
    public string Value { get; }

    /// <summary>Require a single OrionGrant permission.</summary>
    /// <param name="permission">The permission the principal must hold.</param>
    public static OrionGrantRequirement ForPermission(string permission)
    {
        ArgumentException.ThrowIfNullOrEmpty(permission);
        return new OrionGrantRequirement(OrionGrantRequirementKind.Permission, permission);
    }

    /// <summary>Require a named OrionGrant policy.</summary>
    /// <param name="policyName">The OrionGrant policy the principal must satisfy.</param>
    public static OrionGrantRequirement ForPolicy(string policyName)
    {
        ArgumentException.ThrowIfNullOrEmpty(policyName);
        return new OrionGrantRequirement(OrionGrantRequirementKind.Policy, policyName);
    }
}
