# Firstboot contract seal follow-up

This document records the next additive hardening step for the passive firstboot release-gate evidence chain.

## Purpose

The proposed contract seal should consume only the aggregate `FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_*` sidecar and emit a final `FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_*` sidecar for release review, dashboards, and recovery handoff.

## Security boundary

The helper must remain read-only and aggregate-only. It must not source shell content, inspect raw telemetry, read packet captures, open sockets, alter firewall rules, change services, mutate model or dataset files, approve restore execution, or modify host or VM state.

## Fail-closed behavior

The helper should return deferred/stop when the manifest smoke summary is missing, malformed, privacy-scope mismatched, blocker-inconsistent, expected-artifact-empty, marked pass while failed, or inconsistent with the manifest smoke component identity.

## Rollback

Rollback is removal of the optional helper from ISO packaging and firstboot refresh wiring. The existing manifest smoke JSON, Markdown, and `.summary.env` artifacts remain authoritative.
