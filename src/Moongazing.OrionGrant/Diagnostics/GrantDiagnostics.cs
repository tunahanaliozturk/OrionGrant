namespace Moongazing.OrionGrant.Diagnostics;

using System.Diagnostics.Metrics;

/// <summary>
/// OpenTelemetry instrumentation for authorization. Exposes a <see cref="Meter"/> named
/// <c>Moongazing.OrionGrant</c> with an outcome-tagged decision counter. Registered as a singleton;
/// dispose it to release the meter.
/// </summary>
public sealed class GrantDiagnostics : IDisposable
{
    /// <summary>The meter name OpenTelemetry consumers subscribe to.</summary>
    public const string MeterName = "Moongazing.OrionGrant";

    private readonly Meter meter;
    private readonly string? instanceTag;

    /// <summary>Create the meter and its instruments.</summary>
    public GrantDiagnostics()
        : this(instanceTag: null)
    {
    }

    /// <summary>
    /// Create the meter and its instruments, optionally tagging every measurement with an
    /// <c>instance</c> tag.
    /// </summary>
    /// <param name="instanceTag">
    /// An optional, stable identifier emitted as an <c>instance</c> tag on every measurement. The
    /// meter is shared by name across all <see cref="GrantDiagnostics"/> instances, so a listener
    /// that filters by meter name (rather than by instrument instance) will otherwise aggregate
    /// measurements from every instance in the process and double-count. Set this when more than one
    /// instance can coexist (multi-tenant hosts, tests) so listeners can disambiguate by tag.
    /// </param>
    public GrantDiagnostics(string? instanceTag)
    {
        meter = new Meter(MeterName, "0.2.0");
        this.instanceTag = string.IsNullOrEmpty(instanceTag) ? null : instanceTag;
        Decisions = meter.CreateCounter<long>(
            "oriongrant.decisions",
            unit: "{decision}",
            description: "Authorization decisions, tagged outcome (granted/denied) and kind (permission/policy/resource).");
    }

    /// <summary>Counts authorization decisions.</summary>
    public Counter<long> Decisions { get; }

    /// <summary>
    /// The instance tag emitted on every measurement, or null when this instance is not scoped.
    /// </summary>
    public string? InstanceTag => instanceTag;

    /// <summary>Record a decision.</summary>
    /// <param name="granted">Whether access was granted.</param>
    /// <param name="kind">The decision kind (permission, policy, or resource).</param>
    public void Record(bool granted, string kind)
    {
        var outcome = new KeyValuePair<string, object?>("outcome", granted ? "granted" : "denied");
        var kindTag = new KeyValuePair<string, object?>("kind", kind);

        if (instanceTag is null)
        {
            Decisions.Add(1, outcome, kindTag);
            return;
        }

        Decisions.Add(1,
            outcome,
            kindTag,
            new KeyValuePair<string, object?>("instance", instanceTag));
    }

    /// <inheritdoc />
    public void Dispose() => meter.Dispose();
}
