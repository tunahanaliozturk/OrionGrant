namespace Moongazing.OrionGrant.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of <see cref="GrantDiagnostics"/>: the public meter name, the decision counter, the
/// outcome/kind tags it emits, and that authorization decisions flow through to the meter. A
/// <see cref="MeterListener"/> captures measurements so the tags can be asserted end to end.
/// </summary>
[Collection("MeterListener")]
public sealed class GrantDiagnosticsTests
{
    private sealed record Measurement(long Value, string Outcome, string Kind);

    private static List<Measurement> Collect(Action<GrantDiagnostics> act)
    {
        var captured = new List<Measurement>();
        using var diagnostics = new GrantDiagnostics();

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            // Filter on this diagnostics' own counter instance, not the (shared) meter name. Other
            // tests construct GrantDiagnostics with the same meter name and run in parallel, so a
            // name filter would capture their measurements too.
            if (ReferenceEquals(instrument, diagnostics.Decisions))
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, state) =>
        {
            string outcome = string.Empty;
            string kind = string.Empty;
            foreach (var tag in tags)
            {
                if (tag.Key == "outcome")
                {
                    outcome = (string)tag.Value!;
                }
                else if (tag.Key == "kind")
                {
                    kind = (string)tag.Value!;
                }
            }

            captured.Add(new Measurement(value, outcome, kind));
        });
        listener.Start();

        act(diagnostics);

        listener.RecordObservableInstruments();
        return captured;
    }

    [Fact]
    public void MeterName_is_the_documented_constant()
    {
        Assert.Equal("Moongazing.OrionGrant", GrantDiagnostics.MeterName);
    }

    [Fact]
    public void Record_emits_a_measurement_tagged_with_outcome_and_kind()
    {
        var measurements = Collect(d => d.Record(granted: true, "permission"));

        var measurement = Assert.Single(measurements);
        Assert.Equal(1, measurement.Value);
        Assert.Equal("granted", measurement.Outcome);
        Assert.Equal("permission", measurement.Kind);
    }

    [Fact]
    public void Record_tags_a_denied_decision()
    {
        var measurements = Collect(d => d.Record(granted: false, "policy"));

        var measurement = Assert.Single(measurements);
        Assert.Equal("denied", measurement.Outcome);
        Assert.Equal("policy", measurement.Kind);
    }

    [Fact]
    public void Authorize_records_a_permission_decision_through_the_meter()
    {
        var measurements = Collect(d =>
        {
            var authorizer = new GrantAuthorizer(
                new OrionGrantBuilder().BuildRoles(),
                new OrionGrantBuilder().BuildPolicies(),
                d);
            var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
            authorizer.Authorize(principal, "orders:read");
        });

        var measurement = Assert.Single(measurements);
        Assert.Equal("granted", measurement.Outcome);
        Assert.Equal("permission", measurement.Kind);
    }

    [Fact]
    public void AuthorizePolicy_records_a_policy_decision_through_the_meter()
    {
        var measurements = Collect(d =>
        {
            var builder = new OrionGrantBuilder()
                .AddPolicy("orders.read", PolicyMode.RequireAny, "orders:read");
            var authorizer = new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), d);
            var principal = new GrantPrincipal { Subject = "u1" };
            authorizer.AuthorizePolicy(principal, "orders.read");
        });

        var measurement = Assert.Single(measurements);
        Assert.Equal("denied", measurement.Outcome);
        Assert.Equal("policy", measurement.Kind);
    }

    [Fact]
    public void Unknown_policy_is_recorded_as_a_denied_policy_decision()
    {
        var measurements = Collect(d =>
        {
            var authorizer = new GrantAuthorizer(
                new OrionGrantBuilder().BuildRoles(),
                new OrionGrantBuilder().BuildPolicies(),
                d);
            authorizer.AuthorizePolicy(new GrantPrincipal { Subject = "u1" }, "missing");
        });

        var measurement = Assert.Single(measurements);
        Assert.Equal("denied", measurement.Outcome);
        Assert.Equal("policy", measurement.Kind);
    }

    [Fact]
    public void Dispose_can_be_called_more_than_once()
    {
        var diagnostics = new GrantDiagnostics();
        diagnostics.Dispose();

        var exception = Record.Exception(() => diagnostics.Dispose());
        Assert.Null(exception);
    }
}
