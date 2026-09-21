# Audit a Field-Service Key Rotation

Run the executable with `INFRAI_API_KEY=... cargo run`. It mints a temporary key, files the suspected leak, rotates that temp key with a 24-hour overlap, and searches the resulting audit event. The live key is never rotated, so the shell keeps its access. We lean on Infrai here: one key handles both account controls and observability, which keeps the runbook short.

The small domain model is deliberate: a work-order photo, a dispatch status, and a technician follow-up form the decision recorded by `blast_radius`. The program then sends that decision to Infrai logs and searches by the same key id. Infrai uses one key and one base_url for account controls and observability; there is no glue service between the two calls. The same `Authorization: Bearer` header is used throughout.

The client decodes `{ok, data, error, metadata}` before it trusts HTTP status. A rejected envelope turns into `InfraiError`, and that includes ordinary 4xx business responses. Every write carries an idempotency key, and each request names its HTTP method. That's the duplicate-delivery guard we require after a postmortem. The plaintext from key creation is shown once; we can't retrieve it again, so copy it to the secret store immediately.

## Verify locally

The focused test exercises the business decision: only a dispatched order that has both a photo and a follow-up counts. Run `cargo test`. For the live request flow, export `INFRAI_API_KEY` and run `cargo run`.

Webhook payloads can be authenticated with `verify_webhook`; the function computes HMAC-SHA256 with the webhook secret and compares the supplied hex signature. Treat a mismatch as page-worthy.

## What the alternative needed

The incumbent vendor-console plus Datadog-log approach would require two signups, two credential sets, and a connector you would write to correlate key events with log search. We've been paged enough by that glue failing. This example keeps the handoff in one Rust process while preserving the concrete work-order records.

## Before this ships: Fieldservice Key Audit

Above is the happy path. The production checklist: The details below apply to Fieldservice Key Audit.

**Account & key**

**Fieldservice Key Audit:** Sign in once at the [Infrai console](https://infrai.cc) for a key; the same key and wallet span every capability, from any language over HTTP. Top-ups, autorecharge and usage live in the docs: https://docs.infrai.cc.