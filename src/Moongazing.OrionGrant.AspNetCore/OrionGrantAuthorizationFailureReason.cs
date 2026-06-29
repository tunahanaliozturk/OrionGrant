namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.AspNetCore.Authorization;

using GrantResult = Moongazing.OrionGrant.AuthorizationResult;

/// <summary>
/// An <see cref="AuthorizationFailureReason"/> that carries the OrionGrant
/// <see cref="Moongazing.OrionGrant.AuthorizationResult"/> behind a denied authorization decision, so a caller inspecting
/// <c>AuthorizationFailure.FailureReasons</c> (or a custom <c>IAuthorizationMiddlewareResultHandler</c>)
/// can read the structured <see cref="DenialReason"/> and surface it as, for example, an RFC 9457
/// ProblemDetails payload, rather than only seeing the framework's opaque failure.
/// </summary>
/// <remarks>
/// The base <see cref="AuthorizationFailureReason.Message"/> is the OrionGrant
/// <see cref="Moongazing.OrionGrant.AuthorizationResult.FailureReason"/>, so existing message-only consumers keep working;
/// <see cref="Denial"/> exposes the structured cause for callers that branch on it.
/// </remarks>
public sealed class OrionGrantAuthorizationFailureReason : AuthorizationFailureReason
{
    /// <summary>Create the failure reason from a denied OrionGrant result.</summary>
    /// <param name="handler">The handler that produced the failure.</param>
    /// <param name="requirement">The OrionGrant requirement that was not satisfied.</param>
    /// <param name="result">The denied OrionGrant result whose reason is surfaced.</param>
    public OrionGrantAuthorizationFailureReason(
        IAuthorizationHandler handler,
        OrionGrantRequirement requirement,
        GrantResult result)
        : base(handler, MessageFor(result))
    {
        ArgumentNullException.ThrowIfNull(requirement);
        ArgumentNullException.ThrowIfNull(result);
        Requirement = requirement;
        Result = result;
    }

    /// <summary>The OrionGrant requirement that failed.</summary>
    public OrionGrantRequirement Requirement { get; }

    /// <summary>The full denied OrionGrant result.</summary>
    public GrantResult Result { get; }

    /// <summary>
    /// The structured denial cause from the OrionGrant result, or null when the result carried only
    /// a message. Lets a consumer branch on <see cref="DenialKind"/> and read the relevant
    /// identifiers without parsing <see cref="AuthorizationFailureReason.Message"/>.
    /// </summary>
    public DenialReason? Denial => Result.Denial;

    private static string MessageFor(GrantResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.FailureReason ?? "OrionGrant authorization failed.";
    }
}
