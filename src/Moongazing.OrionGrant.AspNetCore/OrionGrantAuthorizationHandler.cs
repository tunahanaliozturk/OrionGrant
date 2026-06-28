namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.AspNetCore.Authorization;

using GrantResult = Moongazing.OrionGrant.AuthorizationResult;

/// <summary>
/// The <see cref="AuthorizationHandler{TRequirement}"/> that evaluates an
/// <see cref="OrionGrantRequirement"/> for the current <see cref="System.Security.Claims.ClaimsPrincipal"/>:
/// it resolves the principal's OrionGrant grants through <see cref="IGrantPrincipalResolver"/> and
/// runs the matching OrionGrant check on <see cref="IGrantAuthorizer"/>. On success it succeeds the
/// requirement; on denial it calls <see cref="AuthorizationHandlerContext.Fail(AuthorizationFailureReason)"/>
/// with an <see cref="OrionGrantAuthorizationFailureReason"/> carrying the structured
/// <see cref="DenialReason"/>.
/// </summary>
/// <remarks>
/// When the authorization call supplies a resource (resource-based authorization), a permission
/// requirement is evaluated with OrionGrant's object-level / ownership-aware overload against the
/// resource's <see cref="ResourceContext"/>. An unresolved principal (anonymous or no subject claim)
/// fails the requirement with a denied result rather than throwing.
/// </remarks>
public sealed class OrionGrantAuthorizationHandler : AuthorizationHandler<OrionGrantRequirement>
{
    private readonly IGrantAuthorizer authorizer;
    private readonly IGrantPrincipalResolver principalResolver;

    /// <summary>Create the handler.</summary>
    /// <param name="authorizer">The OrionGrant authorizer that decides the check.</param>
    /// <param name="principalResolver">Resolves the OrionGrant principal for the current user.</param>
    public OrionGrantAuthorizationHandler(
        IGrantAuthorizer authorizer,
        IGrantPrincipalResolver principalResolver)
    {
        ArgumentNullException.ThrowIfNull(authorizer);
        ArgumentNullException.ThrowIfNull(principalResolver);
        this.authorizer = authorizer;
        this.principalResolver = principalResolver;
    }

    /// <inheritdoc />
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OrionGrantRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);

        var principal = await principalResolver
            .ResolveAsync(context.User, CancellationToken.None)
            .ConfigureAwait(false);

        if (principal is null)
        {
            Fail(context, requirement, GrantResult.Denied(
                "No OrionGrant principal could be resolved for the current user.",
                DenialReason.MissingPermission(requirement.Value)));
            return;
        }

        var result = Evaluate(principal, requirement, context.Resource);

        if (result.IsGranted)
        {
            context.Succeed(requirement);
        }
        else
        {
            Fail(context, requirement, result);
        }
    }

    private GrantResult Evaluate(
        GrantPrincipal principal,
        OrionGrantRequirement requirement,
        object? resource)
    {
        if (requirement.Kind == OrionGrantRequirementKind.Policy)
        {
            return authorizer.AuthorizePolicy(principal, requirement.Value);
        }

        return resource switch
        {
            OrionGrantResource og =>
                authorizer.Authorize(principal, requirement.Value, og.Context, og.Options),
            ResourceContext ctx =>
                authorizer.Authorize(principal, requirement.Value, ctx),
            _ => authorizer.Authorize(principal, requirement.Value),
        };
    }

    private void Fail(
        AuthorizationHandlerContext context,
        OrionGrantRequirement requirement,
        GrantResult result)
    {
        context.Fail(new OrionGrantAuthorizationFailureReason(this, requirement, result));
    }
}
