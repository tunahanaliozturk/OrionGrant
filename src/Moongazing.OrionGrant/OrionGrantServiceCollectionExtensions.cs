namespace Moongazing.OrionGrant;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Registration helpers for OrionGrant.
/// </summary>
public static class OrionGrantServiceCollectionExtensions
{
    /// <summary>
    /// Register the authorizer, diagnostics, and the role and policy registries built from the
    /// <paramref name="configure"/> callback.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Declares roles and policies. Optional.</param>
    public static IServiceCollection AddOrionGrant(
        this IServiceCollection services,
        Action<OrionGrantBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var builder = new OrionGrantBuilder();
        configure?.Invoke(builder);

        var cache = builder.BuildEffectiveGrantCache();

        services.TryAddSingleton(builder.BuildRoles());
        services.TryAddSingleton(builder.BuildPolicies());
        services.TryAddSingleton<GrantDiagnostics>();

        // Register the cache only when one was requested, so the default container has no extra
        // singleton and the authorizer is constructed with a null cache (the pure 0.3.0 path).
        if (cache is not null)
        {
            services.TryAddSingleton(cache);
        }

        services.TryAddSingleton<IGrantAuthorizer>(sp => new GrantAuthorizer(
            sp.GetRequiredService<RoleRegistry>(),
            sp.GetRequiredService<PolicyRegistry>(),
            sp.GetRequiredService<GrantDiagnostics>(),
            sp.GetService<IEffectiveGrantCache>()));

        return services;
    }
}
