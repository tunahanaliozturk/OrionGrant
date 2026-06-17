# Benchmarks

Micro-benchmarks for OrionGrant's hot paths, built with [BenchmarkDotNet](https://benchmarkdotnet.org/).
Everything measured here is pure and in-memory: the permission matcher, the authorizer, and the
one-time registration path. There is nothing to mock and no external service to stand up.

The project lives in `benchmarks/Moongazing.OrionGrant.Benchmarks` and references the library
directly. Each class runs on both `net8.0` and `net9.0` (via `[SimpleJob]`) with the memory
diagnoser enabled, so every result reports allocations alongside timing.

## Suites

### `PermissionMatcherBenchmarks`
The core wildcard matcher (`PermissionMatcher`), the split-and-compare routine every decision runs
through.

- `ExactMatch` - an exact segment-for-segment match.
- `TrailingWildcard` - a trailing `*` covering several remaining segments (`orders:*` over `orders:read:detail`).
- `MiddleWildcard` - a `*` in a middle segment (`orders:*:read` over `orders:eu:read`).
- `RootWildcard` - the bare `*` that grants everything.
- `NonMatch` - a same-length mismatch that fails on the last segment.
- `IsGrantedByAny_Hit` / `IsGrantedByAny_Miss` - scanning a small granted set for a hit, and for a
  miss that has to walk the whole set.

### `AuthorizerBenchmarks`
The full `GrantAuthorizer` path: role expansion into an effective permission set (a `HashSet`
union, the main per-call allocation) followed by matching.

- `EffectivePermissions` - role expansion and the direct-permission union, in isolation.
- `Authorize_Granted` / `Authorize_Denied` - a single permission check that succeeds, and one that
  scans the whole effective set before denying.
- `AuthorizePolicy_RequireAny` - a `RequireAny` policy that short-circuits on the first match.
- `AuthorizePolicy_RequireAll` - a `RequireAll` policy that must satisfy every listed permission.

### `RegistrationBenchmarks`
The one-time startup path.

- `RegisterAndResolve` - declares a handful of roles and policies through `AddOrionGrant`, builds
  the provider, and resolves `IGrantAuthorizer`, forcing the immutable registries to be built. Not
  on the request hot path, but it is what runs at application boot.

## Running

From the repository root:

```
dotnet run -c Release --project benchmarks/Moongazing.OrionGrant.Benchmarks
```

That lists the suites and lets you pick interactively. To run everything:

```
dotnet run -c Release --project benchmarks/Moongazing.OrionGrant.Benchmarks -- --filter "*"
```

To run a single suite, filter by class name:

```
dotnet run -c Release --project benchmarks/Moongazing.OrionGrant.Benchmarks -- --filter "*PermissionMatcherBenchmarks*"
```

BenchmarkDotNet writes full reports (Markdown, HTML, CSV) under
`benchmarks/Moongazing.OrionGrant.Benchmarks/BenchmarkDotNet.Artifacts`.

> Run benchmarks in `Release` on an otherwise idle machine. No measured numbers are committed to
> this repository; collect your own on the hardware you care about, since results are
> machine-specific.
