# Reed–Solomon parity for the stego payload

## Goal

Today a single flipped bit anywhere in the embedded payload loses everything. AES-GCM is all-or-nothing: the tag check fails and `decrypt` returns an error indistinguishable from a wrong password. There is no partial recovery and no early warning.

This change adds forward error correction so that a carrier which has suffered scattered bit damage still decodes, and so that `verify` can report *how much* correction was needed — turning silent degradation into a measurable signal before it becomes unrecoverable.

## Non-goals

RS parity does **not** protect against anything that reprocesses the image. Resizing, re-compression, format conversion, colour management, or a social platform's thumbnailer destroy essentially every low bit. That is a loss rate of ~50% of payload bits, orders of magnitude beyond any practical code rate. Do not present this feature as making the carrier survive editing or uploading — it does not, and saying so would be worse than not having it.

The target is bit rot, partial media failure, and small copy errors.

## Where the code goes in the pipeline

Current: `payload → pack → AES-256-GCM → embed`

New: `payload → pack → AES-256-GCM → RS encode → embed`

**RS must be applied to the ciphertext, outside the AEAD.** This is the only placement that works, and the reasoning matters:

- *Before* encryption is useless. AES-GCM diffuses errors — one wrong bit in the ciphertext corrupts its whole block and fails the tag regardless of what redundancy sits inside the plaintext. The correction would never run.
- *After* encryption, corruption is repaired before GCM ever sees the bytes, so the tag check passes on a carrier that would otherwise have been a total loss.

Security notes for this ordering:

- Parity is computed over ciphertext, which is already indistinguishable from random, so the parity bytes are too. No plaintext structure leaks.
- RS runs *before* authentication, so a tampered carrier may be "corrected" into different wrong bytes. This is safe: GCM still rejects it, because an attacker cannot produce a valid tag. Mis-correction degrades to the existing failure mode, never to accepted forgery.
- Parity is a deterministic function of ciphertext. It adds no entropy and must not be treated as contributing any.

## The part that is easy to get wrong

**The header is more fragile than the payload, and protecting only the ciphertext leaves the real single points of failure untouched.**

Today's header is 33 bytes: 16 salt, 12 nonce, 1 version, 4 length. Every one of them is fatal if corrupted:

- one bad salt bit → different Argon2 output → wrong key → total loss
- one bad nonce bit → GCM tag fails → total loss
- one bad length bit → wrong number of slots read → total loss
- one bad version bit → rejected as an unknown format

Wrapping the ciphertext in parity while leaving these bare would produce a feature that looks like it works and still dies to a single flipped bit in 33. The header therefore gets its own redundancy, by **replication with per-bit majority vote**, which is simpler than a second RS layer and needs no decoder state to bootstrap.

Use `HEADER_REPLICAS = 5`. Write five consecutive copies; on read, take each bit position's majority across the five. This tolerates two corrupted copies at every bit position independently. Cost is 1360 slots total, negligible against millions.

Majority must be per **bit**, not per copy — scattered damage typically touches every copy somewhere, so "pick the first intact copy" fails exactly when it is needed.

## Format

This is a breaking format change. It bumps `FORMAT_VERSION` to `2` and existing images will not decode.

### Public path (slots from `public_path`, before any key exists)

Replicated 5×, 16 bytes per copy = 640 slots:

| field | bytes | notes |
|---|---|---|
| `salt` | 16 | Argon2 salt, as today |

The public path holds **nothing of known value**. This is deliberate and must not be changed: a constant at fixed public slots is a free distinguisher. Anyone with this source could read those slots, test for the expected value, and get a one-in-256 answer to "is this image a carrier" without any password. The salt is safe there only because it is random and therefore indistinguishable from the carrier's own low bits.

### Keyed path (slots from `payload_path`, after key derivation)

Replicated 5×, 18 bytes per copy = 720 slots, the whole block XOR-masked with `header_mask` as the length already is:

| field | bytes | notes |
|---|---|---|
| `version` | 1 | format version — `2` for this change (v1 is the pre-parity format) |
| `nonce` | 12 | GCM nonce, as today |
| `parity_per_block` | 1 | RS parity bytes per 255-byte block, `P` |
| `cipher_len` | 4 | **unencoded** ciphertext length, big-endian |

Store the *unencoded* length. The decoder derives the block structure and the encoded length from `cipher_len` and `P`, which is less error-prone than storing both and risking disagreement.

`version` already exists in v1 as the first byte of the masked keyed header; keep it first so the field can always be found at a fixed offset regardless of what follows it.

**Validate `cipher_len`'s bounds before reporting a version mismatch.** Under a wrong password every one of these fields is noise, and a version byte read from noise would otherwise produce "this carrier is format v212" where the honest answer is the generic integrity failure. The length bounds check rejects random headers with probability ~1 − 2⁻¹⁵, so passing it is good evidence the header is genuine and its version worth naming. v1 already does this; preserve the order.

Consequence to record: because the version is only legible after key derivation, **the Argon2 parameters, the salt length and the public slot placement are frozen across all versions.** Everything downstream of derivation is free to change. If one of those frozen things ever must move, it needs a different mechanism than this byte — and that mechanism will have to solve the distinguisher problem above.

### Payload

RS-encoded ciphertext immediately follows the replicated keyed header.

## Algorithms

Let `P = parity_per_block`, `K = 255 - P`, `L = cipher_len`.

```
blocks       = ceil(L / K)
encoded_len  = L + blocks * P
```

### Encode

1. Split ciphertext into `blocks` chunks of `K` bytes; the final chunk may be short. Do **not** pad it out in the output — use a shortened code, so a short final block produces `len(chunk) + P` bytes. Padding would waste capacity and change `encoded_len`.
2. RS-encode each chunk systematically over GF(256), appending `P` parity bytes.
3. Concatenate. Result is `encoded_len` bytes.
4. Capacity check uses `encoded_len`, not `L`. Update the existing check and the `too_small` message accordingly — a payload that fit before may not now.

### Decode

1. Read and majority-resolve the public header to get `salt`. There is nothing to validate here — every byte of it is random by construction.
2. Derive keys from `salt`.
3. Read and majority-resolve the keyed header. Validate `cipher_len` is within carrier capacity and `P` is in `0..=64` **before** using either to index, and before trusting `version` beside them.
4. Only once those bounds hold, check `version`. Reject an unrecognised one with a distinct error rather than the generic integrity failure — "this image was written by a different build" is information the user can act on, where "wrong password" would send them looking in the wrong place.
5. Read `encoded_len` bytes from the slot path.
6. RS-decode each block. Count corrected symbols. If any block exceeds its correction capacity, return the existing `INTEGRITY_FAILURE` — do not leak which stage failed.
7. GCM decrypt, then `unpack` as today.

### Correction reporting

`recover` should return the corrected-symbol count alongside the plaintext, so `verify` can surface it. This is the feature's main practical payoff:

```
✅ Readable: 9880 bytes recovered from 'x.png'.
   SHA3-256: 982ace...
   ⚠️  23 symbols corrected (of 1280 parity capacity) — the carrier is degrading.
```

A clean read prints nothing extra. Suggest re-writing the carrier when corrections exceed ~25% of capacity.

## Parameters

Default `P = 32`, giving RS(255, 223): the classic configuration, ~12.5% overhead, corrects up to 16 byte-errors per 255-byte block.

Because the keyed shuffle already scatters consecutive payload bits across the whole frame, random bit rot arrives as isolated single-bit errors in distinct bytes — one symbol error each, spread evenly over blocks. At `P = 32` that tolerates roughly 6% of payload *bytes* damaged, i.e. a bit error rate near 0.8%. Note this is the favourable case; the shuffle is working for us here.

Expose `--parity <bytes>` on `encode`, default 32, range 0–64. `P = 0` disables encoding entirely and must still write a well-formed header so that unprotected payloads stay representable in the new format.

## API changes

- `embed` / `extract`: header read/write moves behind replication helpers. Suggested: `write_replicated(bits, field)` and `read_replicated(slots, len)`.
- `recover(input, password) -> Result<(Zeroizing<Vec<u8>>, Corrections)>` where `Corrections { corrected: usize, capacity: usize }`.
- `decode` ignores the count; `verify` prints it.
- `encode` gains the `parity` argument threaded from clap.

## Crate

`reed-solomon` (mersinvald) matches the model needed here — true error correction over GF(256) at unknown positions, which is what bit rot requires.

Do **not** reach for `reed-solomon-erasure` or `reed-solomon-simd` without adding per-shard checksums: those are *erasure* codes. They recover shards known to be missing, and cannot locate an error on their own. Bit rot gives no such location information.

Verify the chosen crate supports shortened blocks for the final chunk; if it does not, zero-pad internally and strip after decode, keeping `encoded_len` arithmetic as specified above.

## Dependency

**Done.** The format version byte shipped as part of v1 — `FORMAT_VERSION` in `src/main.rs`, the first byte of the masked keyed header, with the placement rationale in its doc comment. This change bumps it to `2`.

Read that comment before touching the header layout; it records why the byte is keyed rather than public, and what that costs.

## Tests

1. **Round trip, no damage** — every `P` in {0, 8, 32, 64}, byte-exact.
2. **Correctable damage** — flip `P/2` bytes in a block; must recover, and report a non-zero corrected count.
3. **Uncorrectable damage** — flip `P` bytes in one block; must return `INTEGRITY_FAILURE`, not a panic and not wrong plaintext.
4. **Header survives replication damage** — corrupt two of five replicas at assorted bit positions; must still decode.
5. **Header beyond replication** — corrupt three of five at one bit position; must fail cleanly.
6. **Version rejection** — write version 99 into an otherwise valid header; must report a distinct version error, not the generic integrity failure. `an_unknown_format_version_is_named` in `src/main.rs` already does this for v1 and shows how to forge the header.
7. **Capacity accounting** — a payload whose `encoded_len` is exactly carrier capacity must encode; one byte more must be refused with the `too_small` message.
8. **Malicious header** — `P = 0xFF`, `cipher_len = 0xFFFFFFFF`; must be rejected by validation before any indexing.

Tests 3, 5 and 8 are the ones that matter. The failure mode to avoid is a corrupted carrier that panics, hangs on an absurd length, or returns plausible but wrong plaintext.
