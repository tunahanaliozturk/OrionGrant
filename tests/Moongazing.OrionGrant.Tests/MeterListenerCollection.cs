namespace Moongazing.OrionGrant.Tests;

using Xunit;

/// <summary>
/// Groups the tests that attach a <see cref="System.Diagnostics.Metrics.MeterListener"/> to the
/// shared <c>Moongazing.OrionGrant</c> meter into a single non-parallel collection. Each test still
/// filters by its own instrument instance, but serializing them keeps the instance-scoping
/// assertions deterministic and avoids any cross-talk while the meter name is shared process-wide.
/// </summary>
[CollectionDefinition("MeterListener", DisableParallelization = true)]
public sealed class MeterListenerCollectionDefinition
{
}
