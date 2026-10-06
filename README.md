# grit — encrypted steganography for PNG carriers

Encrypts a file with AES-256-GCM under an Argon2id-derived key, then hides the ciphertext in the low bits of a PNG photograph. The output is a valid image that looks and opens like the original.

```
cargo clean
cargo build --release
export PASSWORD="a quick brown fox jumps over the lazy dog"

./target/release/grit encode -i ./etc/wave.png -o ./target/done.png -t ./etc/payload.txt
./target/release/grit verify -i ./target/done.png -t ./etc/payload.txt
./target/release/grit decode -i ./target/done.png > ./target/done.txt
diff ./etc/payload.txt ./target/done.txt
```

## Status

**This is a learning project and it has not been audited. Do not use it to store/backup/transfer any sensitive data!**

For anything whose loss would hurt, use [`age`](https://github.com/FiloSottile/age). It does the encryption properly, in one command, reviewed by many more people.

The one thing this adds over `age` is that the output is a photograph rather than something that announces itself as ciphertext. If you don't specifically need that, you don't need this.

## Build

```
cargo build --release
```

Binary lands at `target/release/grit`.

## Commands

### `encode`

```
grit encode -i <carrier.png> -o <output.png> -t <file-to-hide>
```

Reads the carrier, embeds the encrypted payload, writes a new PNG. The carrier is never modified. Fails if the payload doesn't fit, reporting the dimensions that would be needed.

Pointing `-o` at the carrier is refused — the comparison resolves symlinks and `./photo.png` against `photo.png`, so it isn't fooled by spelling. Write the result somewhere else and delete the carrier yourself; keeping the two side by side is the mistake that undoes everything else.

### `decode`

```
grit decode -i <carrier.png> > recovered
```

Writes the recovered bytes to **stdout**, raw and byte-exact — redirect it. Status messages go to stderr, so they don't contaminate the output. Binary payloads survive intact.

### `verify`

```
grit verify -i <carrier.png>               # readable? print its digest
grit verify -i <carrier.png> -t <original> # readable AND identical to this file?
```

Confirms the payload still decodes without printing it, and reports a SHA3-256 digest of what it found. Exits non-zero on failure, so it works in a cron job.

Record that digest when you create a carrier. Years later, with the original long gone, a matching digest tells you the image is still intact. **An untested backup is not a backup.**

## Passwords

In order of preference:

1. **`$PASSWORD`** — `export PASSWORD="..."`
2. **Interactive prompt** — the default when the variable is unset; input hidden
3. **`-p/--password`** — works, warns, and should be your last resort

`argv` is readable by every other process on the machine via `ps`, and lands in your shell history. The environment is better but not private either — the kernel keeps the block for the process's lifetime. Only the prompt leaves nothing behind outside this program's own memory.

Key material, the password and the plaintext are zeroized on drop. Buffers that reallocated while growing are not reachable for wiping; that's a limit of the language, not an oversight.

## Choosing a carrier

**This matters more than any other choice you make.** Measured on real files, embedding the same ~14 KB payload:

| carrier | LSB plane compressibility | file growth |
|---|---|---|
| synthetic noise | 100% (incompressible) | **+0.00×** payload |
| grainy photograph | 96.3% | **+1.18×** payload |
| 4-bit indexed PNG | — | +7.7×, *plus* 69 KB → 511 KB just to convert |
| smooth fractal render | 18.5% | **+18.9×** payload |

One number predicts all of it: **how incompressible the carrier's low bits already are.** You are not hiding data in the image, you are hiding it in the noise the sensor already put there. Where there's no noise floor, PNG bills you ten to nineteen bits of file growth per payload bit, because every flipped bit interrupts a run of zero prediction residuals that DEFLATE was compressing for free.

So:

- **Use a grainy, high-resolution photograph you took yourself.** Foliage, gravel, water, fabric, rust. Higher resolution is strictly better — it lowers the embedding rate for the same payload.
- **Never use a downloaded image.** The original exists publicly, and a diff against it reveals every changed pixel regardless of how good everything else is. Perceptual hashes survive contrast, sharpening and format conversion, so editing a downloaded file does not hide where it came from.
- **Never store the carrier alongside the output.** Same drive, same cloud account, same backup set — whoever gets one gets both, and the diff works perfectly. This is the single failure that undoes everything else. Delete the carrier once you have the stego image and have verified it.
- **Avoid indexed, greyscale and 16-bit PNGs.** The tool warns about these. Embedding forces a conversion to 8-bit RGB that inflates the file, changes the colour type in the header, and — for a palette image — turns 16 distinct colours into hundreds. Counting colours finds that in one pass.
- **Edit before embedding, never after.** Any filter applied afterwards changes pixel values and destroys the payload.

### Stay far below capacity

Capacity is roughly `width × height × 3 / 8` bytes. That is a *physical* limit, not a safety one, and the gap between them is large. Detectability scales with how much of the carrier you disturb; a few hundred bytes in a multi-megapixel photo is invisible to everything tested here, while filling the frame is not.

A seed phrase is ~100–200 bytes. A multi-megapixel photo has millions of slots. That ratio is where this tool is comfortable.

## How it works

```
payload → deflate → AES-256-GCM → scatter into low bits → PNG
```

1. **Compress.** DEFLATE, with a one-byte tag. Input that doesn't shrink (an archive, a JPEG) is stored raw instead — forcing compression on random data only adds bytes. Compression happens *before* encryption, the only order that works: ciphertext is incompressible by design.
2. **Derive.** Argon2id (64 MiB, 3 passes) over the password and a fresh random 16-byte salt, expanded by SHA3-256 into three domain-separated subkeys — one for the cipher, one for the slot permutation, one to mask the header.
3. **Encrypt.** AES-256-GCM with a fresh random 12-byte nonce per image.
4. **Scatter.** Every RGB channel of every pixel is one slot holding one bit; alpha is never touched. Slots are permuted twice: first by a fixed public seed, whose opening 128 slots carry the salt — the decoder must find that before it has any key, so its placement cannot depend on one. The rest are permuted again under the password-derived key and carry the nonce, the masked header, and the ciphertext.
5. **Write.** LSB *matching*: a channel whose low bit is already correct is left alone; one that is wrong moves up or down by one. Forcing the bit instead (`v & 0xFE | bit`) drives histogram pairs together and is what the chi-square attack detects. Slots past the payload are left untouched.
6. **Save.** The carrier's original colour type and its ancillary chunks (EXIF, ICC profile, resolution, text) are carried over. A photograph that arrives stripped of all metadata announces that a program rewrote it.

The keyed header holds a format version byte, so a future build meets an old image and says so rather than reporting a generic failure indistinguishable from a wrong password. It lives behind the key deliberately: a known constant at fixed public slots would let anyone holding this source test any image for carrier-hood without a password.

## What this protects against

**Reading the message: strong.** AES-256-GCM with per-image random nonces, keys from Argon2id with a per-image random salt. No known break in the construction. Your password is the weak link.

**Noticing the message exists: uncertain, and honestly so.** The classical attacks are defeated — chi-square sits in the natural range for an untouched photograph, the file size shows no anomaly on a good carrier, metadata and colour type are preserved. Several attempts to detect a payload *blind* — with no access to the original image, which is the realistic case — found nothing.

But that is weak evidence. Published steganalysis uses rich models with tens of thousands of features, or trained CNNs, over corpora of thousands of image pairs. None of that was tested here and a toy detector's failure proves little.

Working against any such detector is **cover source mismatch**: an ordinary contrast adjustment moves the statistics roughly four times further than a 50 KB payload does, and in the opposite direction. There is no single "natural image" baseline — there's one per camera, per raw converter, per edit, per export — and a detector needs to know which pipeline produced your file.

Treat "undetectable" as unproven in both directions.

## What this does not protect against

- **Any reprocessing of the image.** Resizing, re-compression, format conversion, a messaging app's thumbnailer — all destroy the payload silently. You find out when the integrity check fails. Move the file as *bytes*: `scp`, `rsync`, a USB stick. Test the channel with a throwaway carrier and `verify` before trusting it.
- **Corruption.** GCM is all-or-nothing: one flipped bit loses everything, with no partial recovery. Reed–Solomon parity would fix this; see [`doc/NEXT.md`](doc/NEXT.md) for the spec.
- **Someone who has the original carrier.** Unbeatable, and the reason the carrier must be yours, unpublished, and not stored beside the output.
- **A weak password.** Argon2id makes guessing expensive, not impossible.

## Development

```
cargo test --release
cargo clippy --release --all-targets
```

Tests cover the round trip at several payload sizes and up to exact capacity, wrong-password rejection, carrier-too-small, the LSB-matching invariants (nothing moves by more than one, alpha never moves, saturated channels stay in range), PNG chunk parsing against truncated and malformed input, compression in both modes, and format version rejection.

`doc/NEXT.md` holds a ready-to-implement spec for Reed–Solomon parity.

## License

MIT — see [LICENSE](LICENSE).
