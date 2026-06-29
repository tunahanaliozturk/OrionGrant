namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// A builder returned by
/// <see cref="OrionGrantAspNetCoreServiceCollectionExtensions.AddOrionGrantAuthorization(IServiceCollection, Action{OrionGrantBuilder})"/>
/// that exposes the underlying <see cref="IServiceCollection"/> so callers can replace the default
/// <see cref="IGrantPrincipalResolver"/> or configure the claims and policy-name options with the
/// standard options pattern.
/// </summary>
public interface IOrionGrantAspNetCoreBuilder
{
    /// <summary>The service collection the OrionGrant ASP.NET Core services were registered into.</summary>
    IServiceCollection Services { get; }
}
