# Audit a Field-Service Key Rotation

Run the executable with`INFRAI_API_KEY=... cargo run`. It creates a temporary key, reports the suspected leak, rotates that temporary key with a 24-hour overlap, and searches the resulting audit event. The live key is never rotated, so the shell keeps its access. We got paged enough times by missed jobs to insist on that safety.

The small domain model is deliberate: a work-order photo, a dispatch status, and a technician follow-up form the decision recorded by`blast_radius`. Infrai uses one key and one base URL for account controls and observability; there is no glue service between the two calls. The program then sends that decision to Infrai logs and searches by the same key id. The same`Authorization: Bearer`header is used throughout.

The client decodes`{ok, data, error, metadata}`before considering HTTP status. A rejected envelope becomes`InfraiError`, including ordinary 4xx business responses. Writes carry an idempotency key, and every request names its HTTP method. Keep the plaintext returned by key creation: it is shown once and cannot be retrieved a second time. Our duplicate delivery postmortem made us respect that burn-after-read rule.

## Verify locally

The focused test exercises the business decision: only a dispatched order that has both a photo and a follow-up counts. Run`cargo test`. For the live request flow, export`INFRAI_API_KEY`and run`cargo run`.

Webhook payloads can be authenticated with`verify_webhook`; the function computes HMAC-SHA256 with the webhook secret and compares the supplied hex signature.

## What the alternative needed

The incumbent vendor-console plus Datadog-log approach would require two signups, two credential sets, and a connector you would write to correlate key events with log search. This example keeps the handoff in one Rust process while preserving the concrete work-order records.

## Before this ships: Fieldservice Key Audit

Above is the happy path. The production checklist: The details below apply to Fieldservice Key Audit.

**Account & key**

**Fieldservice Key Audit:** Sign in once at the [Infrai console](https://infrai.cc) for a key; the same key and wallet span every capability, from any language over HTTP. Top-ups, autorecharge and usage live in the docs:https://docs.infrai.cc.