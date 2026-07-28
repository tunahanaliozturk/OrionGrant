namespace Moongazing.OrionGrant.Diagnostics;

using System.Diagnostics.Metrics;

using Moongazing.Orion.Abstractions.Diagnostics;

/// <summary>
/// OpenTelemetry instrumentation for authorization. Built on the Orion family's
/// <see cref="OrionInstrumentation"/> spine, so it shares the family's naming and static-tag
/// conventions: a <see cref="Meter"/> named <c>Moongazing.OrionGrant</c> (subscribe by that name)
/// exposing the decision counter <c>orion.grant.decisions</c>, tagged outcome and kind. Multi-tenant
/// / multi-region labels configured through <see cref="OrionInstrumentation.SetStaticTags"/> are
/// stamped onto every measurement. Registered as a singleton; dispose it to release the meter.
/// </summary>
public sealed class GrantDiagnostics : OrionInstrumentation
{
    /// <summary>The meter name OpenTelemetry consumers subscribe to.</summary>
    public const string MeterName = "Moongazing.OrionGrant";

    /// <summary>Create the meter and its instruments.</summary>
    public GrantDiagnostics()
        : this(instanceTag: null)
    {
    }

    /// <summary>
    /// Create the meter and its instruments, optionally tagging the meter with an instance scope.
    /// </summary>
    /// <param name="instanceTag">
    /// An optional, stable identifier published on the <see cref="Meter"/> as the
    /// <see cref="OrionInstrumentation.InstanceTagKey"/> (<c>orion.instance</c>) tag. The meter is
    /// shared by name across all <see cref="GrantDiagnostics"/> instances, so a listener that filters
    /// by meter name (rather than by instrument instance) will otherwise aggregate measurements from
    /// every instance in the process. Set this when more than one instance can coexist (multi-tenant
    /// hosts, tests) so listeners can disambiguate by tag.
    /// </param>
    public GrantDiagnostics(string? instanceTag)
        : base(
            OrionTelemetry.ScopeName("OrionGrant"),
            MeterVersion.Value,
            instanceScopeId: string.IsNullOrEmpty(instanceTag) ? null : instanceTag)
    {
        Decisions = Meter.CreateCounter<long>(
            OrionTelemetry.MetricName("grant", "decisions"),
            unit: "{decision}",
            description: "Authorization decisions, tagged outcome (granted/denied) and kind (permission/policy/resource).");
    }

    /// <summary>Counts authorization decisions.</summary>
    public Counter<long> Decisions { get; }

    /// <summary>
    /// The instance scope published on the meter, or null when this instance is not scoped.
    /// Alias of <see cref="OrionInstrumentation.InstanceScopeId"/>.
    /// </summary>
    public string? InstanceTag => InstanceScopeId;

    /// <summary>Record a decision.</summary>
    /// <param name="granted">Whether access was granted.</param>
    /// <param name="kind">The decision kind (permission, policy, or resource).</param>
    public void Record(bool granted, string kind)
    {
        Decisions.Add(1, Compose(
            new KeyValuePair<string, object?>(OrionTelemetry.Tags.Outcome, granted ? "granted" : "denied"),
            new KeyValuePair<string, object?>("kind", kind)));
    }

    // Merge the configured static tags with this measurement's domain tags. The base Tag() helper
    // covers the single-extra case; a decision carries two domain tags, so build the array here.
    // Allocation-free passthrough when no static tags are configured (the common case).
    private KeyValuePair<string, object?>[] Compose(params KeyValuePair<string, object?>[] extra)
    {
        if (StaticTags.Length == 0)
        {
            return extra;
        }

        var all = new KeyValuePair<string, object?>[StaticTags.Length + extra.Length];
        StaticTags.CopyTo(all, 0);
        extra.CopyTo(all, StaticTags.Length);
        return all;
    }
}
