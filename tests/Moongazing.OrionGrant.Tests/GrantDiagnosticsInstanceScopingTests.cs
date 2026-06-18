namespace Moongazing.OrionGrant.Tests;

using System.Collections.Generic;
using System.Diagnostics.Metrics;

using Moongazing.OrionGrant.Diagnostics;

using Xunit;

/// <summary>
/// Coverage of <see cref="GrantDiagnostics"/> instance scoping: the optional <c>instance</c> tag
/// lets a <see cref="MeterListener"/> disambiguate measurements when more than one instance shares
/// the meter name. These tests filter strictly by the instrument <em>instance</em> and run in a
/// non-parallel collection so two coexisting diagnostics objects cannot leak measurements into one
/// another's listener.
/// </summary>
[Collection("MeterListener")]
public sealed class GrantDiagnosticsInstanceScopingTests
{
    private sealed record Measurement(string Outcome, string Kind, string? Instance);

    private static List<Measurement> CollectFrom(GrantDiagnostics diagnostics, System.Action act)
    {
        var captured = new List<Measurement>();

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            // Filter on the specific counter instance, never the shared meter name.
            if (ReferenceEquals(instrument, diagnostics.Decisions))
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, state) =>
        {
            string outcome = string.Empty;
            string kind = string.Empty;
            string? instance = null;
            foreach (var tag in tags)
            {
                switch (tag.Key)
                {
                    case "outcome":
                        outcome = (string)tag.Value!;
                        break;
                    case "kind":
                        kind = (string)tag.Value!;
                        break;
                    case "instance":
                        instance = (string)tag.Value!;
                        break;
                }
            }

            captured.Add(new Measurement(outcome, kind, instance));
        });
        listener.Start();

        act();

        listener.RecordObservableInstruments();
        return captured;
    }

    [Fact]
    public void Unscoped_instance_emits_no_instance_tag()
    {
        using var diagnostics = new GrantDiagnostics();

        var measurements = CollectFrom(diagnostics, () => diagnostics.Record(granted: true, "resource"));

        var measurement = Assert.Single(measurements);
        Assert.Equal("resource", measurement.Kind);
        Assert.Null(measurement.Instance);
    }

    [Fact]
    public void Scoped_instance_tags_every_measurement_with_its_instance()
    {
        using var diagnostics = new GrantDiagnostics(instanceTag: "tenant-a");

        var measurements = CollectFrom(diagnostics, () => diagnostics.Record(granted: false, "permission"));

        var measurement = Assert.Single(measurements);
        Assert.Equal("tenant-a", measurement.Instance);
        Assert.Equal("denied", measurement.Outcome);
    }

    [Fact]
    public void Two_scoped_instances_are_distinguishable_by_their_instance_tag()
    {
        using var a = new GrantDiagnostics(instanceTag: "a");
        using var b = new GrantDiagnostics(instanceTag: "b");

        var fromA = CollectFrom(a, () => a.Record(granted: true, "resource"));
        var fromB = CollectFrom(b, () => b.Record(granted: true, "resource"));

        Assert.Equal("a", Assert.Single(fromA).Instance);
        Assert.Equal("b", Assert.Single(fromB).Instance);
    }

    [Fact]
    public void InstanceTag_is_exposed_and_normalizes_empty_to_null()
    {
        using var scoped = new GrantDiagnostics(instanceTag: "x");
        using var blank = new GrantDiagnostics(instanceTag: "");

        Assert.Equal("x", scoped.InstanceTag);
        Assert.Null(blank.InstanceTag);
    }
}
