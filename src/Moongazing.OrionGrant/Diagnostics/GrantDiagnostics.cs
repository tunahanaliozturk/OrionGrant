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

    /// <summary>Create the meter and its instruments.</summary>
    public GrantDiagnostics()
    {
        meter = new Meter(MeterName, "0.1.0");
        Decisions = meter.CreateCounter<long>(
            "oriongrant.decisions",
            unit: "{decision}",
            description: "Authorization decisions, tagged outcome (granted/denied) and kind (permission/policy).");
    }

    /// <summary>Counts authorization decisions.</summary>
    public Counter<long> Decisions { get; }

    /// <summary>Record a decision.</summary>
    /// <param name="granted">Whether access was granted.</param>
    /// <param name="kind">The decision kind (permission or policy).</param>
    public void Record(bool granted, string kind) =>
        Decisions.Add(1,
            new KeyValuePair<string, object?>("outcome", granted ? "granted" : "denied"),
            new KeyValuePair<string, object?>("kind", kind));

    /// <inheritdoc />
    public void Dispose() => meter.Dispose();
}
