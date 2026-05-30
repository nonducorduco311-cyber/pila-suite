# Demo dataset — ByTE X Bit Platform Community Edition

This directory contains a small synthetic dataset that lets a fresh
Community Edition install show populated dashboards immediately, instead
of landing the user on empty screens.

## What's here today

| File | Records | Size |
|------|---------|------|
| `sample_data/engagements.json` | 5 PSIL engagements | 8765 bytes |

That single file populates the PILA Suite dashboard with five realistic
purple-team engagements documenting a fictional "Demo SOC (synthetic)"
organization onboarding the platform over a six-week period. Each
engagement includes ATT&CK technique mappings, scenario outcomes,
detection results, and computed metrics (detection rate, MTTR, coverage
by tactic). The engagements collectively show a realistic
detect → gap → remediate → validate cycle rather than disconnected
snapshots.

All IP addresses are in IANA documentation ranges (`203.0.113.0/24` per
RFC 5737), so the synthetic data cannot collide with real network space.
All identifiers are deterministic — the same generator inputs always
produce the same UUIDs.

## How the demo will work (planned)

A future commit will add auto-load logic to `api/server_community.py`:

- On startup, if `data/engagements.json` does not exist, the platform
  copies `demo/sample_data/engagements.json` into place and writes a
  marker file at `data/.demo_loaded`.
- A "Demo Mode" banner appears on every dashboard page while the marker
  exists, making it impossible to mistake demo data for real data.
- A "Clear and start fresh" endpoint removes the demo data and the
  marker, letting the user start documenting their own engagements
  without restarting the platform.

That auto-load logic is **not yet shipped** as of this commit. This
file is being staged first so the auto-load implementation has
something to copy from.

## What Community Edition does NOT show

The platform has additional products (LMEP behavioral emulation, IRV
remediation validation, the CODE Suite for detection-rule monitoring,
GHOST for ATT&CK coverage tracking, SENTINEL for posture scoring with
cryptographic evidence chains) that are part of the Professional
Edition. Community Edition currently exposes only the PILA Suite, so
this demo dataset is scoped to what Community can actually display.

Future Community Edition releases may expand what's shown here as more
capability moves into the free tier.

## Regenerating the dataset

The dataset is produced by a deterministic generator script (the same
inputs always produce byte-identical JSON). The generator is currently
kept internal.

## Why this exists

A new user clones the repo, runs `./start.sh`, and expects to see
something — not "no engagements yet, click here to create one." The
empty-dashboard problem kills the evaluation funnel before users
understand what the platform does.

This dataset is the smallest change that fixes that problem. It is
explicitly labeled as synthetic, is easy to clear, and does not
pretend to be more than it is.
