namespace Moongazing.OrionGrant.AspNetCore;

/// <summary>What an <see cref="OrionGrantRequirement"/> asks OrionGrant to evaluate.</summary>
public enum OrionGrantRequirementKind
{
    /// <summary>A single permission requirement, evaluated with the OrionGrant permission check.</summary>
    Permission,

    /// <summary>A named OrionGrant policy requirement, evaluated with the policy check.</summary>
    Policy,
}
