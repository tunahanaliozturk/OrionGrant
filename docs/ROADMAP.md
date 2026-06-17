# OrionGrant Roadmap

Where OrionGrant might go next, and how you can help shape it.

OrionGrant is at `0.1.0`. The core model (hierarchical permissions, wildcard matching, roles, and
all-of / any-of policies) is shipped and stable in shape. This document lists ideas under
consideration, not commitments. There are no dates here on purpose: items move forward when real
workloads ask for them. If something below matters to you, open an issue and say so, that is what
moves an idea up the list.

---

## Guiding principles

These constrain what is worth adding:

- **Stay dependency-light.** The library depends only on
  `Microsoft.Extensions.DependencyInjection.Abstractions`. Anything that would pull in a heavier
  dependency belongs in a separate companion package, not the core.
- **Keep the hot path pure and synchronous.** The matcher and authorizer are allocation-light and
  trivially testable. New features should not compromise that for the common case.
- **Prefer indirection over special cases.** Named policies already let endpoints stay stable while
  requirements change; new capabilities should follow that grain.

---

## Ideas under consideration

These are candidates, not promises, roughly grouped.

### Core authorization

- **Role-to-role inclusion.** Let a role include another role so common bundles compose, with cycle
  detection at registration time.
- **Explicit denies.** A way to subtract a permission from an otherwise-granted set, for carve-outs.
  Needs a clear precedence rule before it would be worth adding.
- **Batch checks.** Evaluate several required permissions or policies for one principal in a single
  call, returning a result per requirement, so callers expanding their effective set repeatedly do
  not have to.

### Ergonomics

- **Effective-set caching per principal.** An optional cache keyed on a principal's roles and direct
  permissions, for call sites that authorize the same principal many times in a request.
- **Result helpers for ASP.NET Core.** Small extension methods to turn a denied `AuthorizationResult`
  into a `ForbidResult` or an RFC 9457 ProblemDetails payload, kept in a companion package so the
  core stays framework-free.
- **Source-generated policy and permission constants.** Generate strongly-typed names from a
  declared policy set so call sites reference symbols instead of magic strings.

### Diagnostics

- **A decision activity source.** Optional `System.Diagnostics.Activity` tracing alongside the
  existing metrics meter, for correlating authorization decisions inside a request trace.
- **Richer denial reasons.** Structured denial data (which permission, which policy, which mode)
  alongside the human-readable string, for callers that want to branch on the cause.

---

## What is intentionally out of scope

To keep the library focused:

- **Permission storage and assignment.** OrionGrant decides; it does not own where roles and grants
  live. Feed it from your own store, JWT claims, or an issuer such as OrionLedger.
- **Authentication.** OrionGrant answers "is this principal allowed", not "who is this principal".
- **A management UI or admin API.** Out of scope for a small, embeddable library.

---

## How to influence this

Open an issue with the `roadmap` label describing the workload you have, not just the feature you
want. Concrete demand is what moves an item from this list into a release.
</content>
