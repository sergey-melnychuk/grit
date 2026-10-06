//! Steganography CLI: AES-256-GCM encrypts a file, then hides the ciphertext in
//! the low bits of a PNG carrier.
//!
//! Carrier layout. Each RGB channel of each pixel is one slot holding one bit;
//! alpha is left alone. Slots are scattered twice. First by a fixed public
//! permutation, whose opening `SALT_BITS` carry the Argon2 salt — the decoder
//! must find that before it has any key, so its placement cannot depend on one.
//! The remaining slots are scattered again under a key derived from the
//! password and that salt, and carry the nonce, a masked header of one format
//! version byte and the ciphertext length, and the ciphertext itself.
//!
//! Bits are written by LSB *matching*: a channel whose low bit is already right
//! is left untouched, and one that is wrong moves up or down by one. Forcing
//! the low bit instead (`v & 0xFE | bit`) drives the histogram pairs (2i, 2i+1)
//! together, which the chi-square attack reads straight off the image.

/*
# The password is taken from $PASSWORD, or asked for at a hidden prompt.
# -p/--password also works, but argv is readable by `ps` and lands in history.

cargo clean
cargo test
cargo build --release
export PASSWORD="a quick brown fox jumps over the lazy dog"

./target/release/grit encode -i ./etc/wave.png -o ./target/done.png -t ./etc/payload.txt
./target/release/grit verify -i ./target/done.png -t ./etc/payload.txt
./target/release/grit decode -i ./target/done.png > ./target/done.txt
diff ./etc/payload.txt ./target/done.txt
*/

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::{Parser, Subcommand};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use image::{DynamicImage, RgbaImage};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_256};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Bits are hidden in R, G and B; alpha would betray them on a transparent pixel.
const CHANNELS: usize = 3;

const SALT_BYTES: usize = 16;
const SALT_BITS: usize = SALT_BYTES * 8;

const NONCE_BYTES: usize = 12;
const NONCE_BITS: usize = NONCE_BYTES * 8;

/// Stamped into every carrier. Nothing is expected to change it — this is an
/// extension vector, kept open so that a later format has somewhere to announce
/// itself. Without it a future build meets an old image and reports the generic
/// integrity failure, which is indistinguishable from a wrong password, and the
/// user has no way to tell those two apart.
///
/// Bump it for any change to what is written after key derivation: payload
/// framing, error-correcting parity, a different cipher. See `doc/NEXT.md`.
///
/// It lives in the *keyed* header rather than the public one on purpose. A
/// known constant at fixed public slots would be a free distinguisher — read
/// eight slots, test for this value, and that is a one-in-256 check for whether
/// any given image is a carrier at all, available to anyone holding this source
/// and no password. Masked and behind the key, it reads as noise.
///
/// The price of that placement: the Argon2 parameters, the salt length and the
/// public slot placement can never change, since the version only becomes
/// legible once keys already exist. Everything downstream of derivation is free.
const FORMAT_VERSION: u8 = 1;

/// Keyed header: one version byte, then the ciphertext length as a big-endian
/// u32, the pair masked with a key-derived pad.
const HEADER_BYTES: usize = 1 + 4;
const HEADER_BITS: usize = HEADER_BYTES * 8;

/// AES-GCM appends a 16 byte authentication tag, so no valid ciphertext is shorter.
const GCM_TAG_LEN: usize = 16;

/// Argon2id at roughly the OWASP figures. Changing any of these changes every
/// derived key, so images written by another setting will no longer open.
const ARGON_MEM_KIB: u32 = 65536;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 1;

/// The sentence is arbitrary; the bytes are not. This seeds the permutation
/// that decides which slots carry the salt, so changing one character moves the
/// salt in every image written afterwards and leaves every existing carrier
/// undecodable — reporting the generic integrity failure, indistinguishable
/// from a wrong password. It is format data wearing a sentence. Leave it be.
const PUBLIC_SEED: [u8; 32] = *b"he who knows life is never late\0";

/// Reported whether the length header or the GCM tag was the thing that failed:
/// which stage rejected the carrier is not the caller's business.
const INTEGRITY_FAILURE: &str = "DECRYPTION CRITICAL FAILURE: Integrity verification failed.";

const PASSWORD_ENV: &str = "PASSWORD";

/// First byte of the plaintext, saying how the rest is stored.
const STORED: u8 = 0;
const DEFLATED: u8 = 1;

/// Carrier chunks copied through to the output. A photograph that arrives
/// stripped of its colour space, resolution and EXIF announces that a program
/// rewrote it, and that is legible without the original to compare against.
///
/// Left behind: PLTE, tRNS, hIST and sPLT, which describe a palette the output
/// no longer has, and sBIT, which would declare the low bits insignificant in
/// the one image whose low bits carry the message.
const PRESERVED_CHUNKS: [&[u8]; 10] = [
    b"cHRM", b"gAMA", b"iCCP", b"sRGB", b"pHYs", b"eXIf", b"tIME", b"tEXt", b"zTXt", b"iTXt",
];

/// PNG signature, then IHDR: 4 length + 4 type + 13 data + 4 CRC. IHDR is
/// fixed-length and must come first, so this offset is the same in every file.
const AFTER_IHDR: usize = 8 + 4 + 4 + 13 + 4;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(name = "grit")]
#[command(about = "AES-GCM Steganography supporting high-capacity PNG carriers", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Внедрить секретный текст в PNG изображение
    Encode {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        /// Visible to `ps` and your shell history; prefer $PASSWORD or the prompt
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        text_file: String,
    },
    /// Извлечь секретный текст из патченного PNG изображения
    Decode {
        #[arg(short, long)]
        input: String,
        /// Visible to `ps` and your shell history; prefer $PASSWORD or the prompt
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Проверить, что сообщение всё ещё читается, ничего не печатая
    Verify {
        #[arg(short, long)]
        input: String,
        /// Visible to `ps` and your shell history; prefer $PASSWORD or the prompt
        #[arg(short, long)]
        password: Option<String>,
        /// Compare the recovered bytes against this file
        #[arg(short, long)]
        text_file: Option<String>,
    },
}

/// Everything the password and salt expand into. Each field is a separate hash
/// of the Argon2 output under its own domain string, so one leaking tells you
/// nothing about the others.
///
/// Wiped when it goes out of scope: left alone, these would sit in the heap
/// until something else happened to reuse the pages, and reach the disk
/// verbatim if the machine swapped or hibernated meanwhile.
#[derive(ZeroizeOnDrop)]
struct Keys {
    cipher_key: [u8; 32],
    shuffle_key: [u8; 32],
    header_mask: [u8; HEADER_BYTES],
}

impl Keys {
    fn derive(password: &str, salt: &[u8; SALT_BYTES]) -> Result<Self> {
        let params = Params::new(ARGON_MEM_KIB, ARGON_PASSES, ARGON_LANES, Some(32))
            .map_err(|e| format!("invalid Argon2 parameters: {e}"))?;

        let mut master = [0u8; 32];
        let hashed = Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
            password.as_bytes(),
            salt,
            &mut master,
        );
        let derived = hashed
            .map_err(|e| format!("key derivation failed: {e}"))
            .map(|()| Self::from_master(&master));

        // Every subkey comes from this, so it outranks all of them. Wiped on the
        // error path too, where Argon2 may still have written part of it.
        master.zeroize();
        derived.map_err(Into::into)
    }

    fn from_master(master: &[u8; 32]) -> Self {
        let mut header_mask = [0u8; HEADER_BYTES];
        header_mask.copy_from_slice(&subkey(master, b"header")[..HEADER_BYTES]);

        Self {
            cipher_key: subkey(master, b"encryption"),
            shuffle_key: subkey(master, b"shuffling"),
            header_mask,
        }
    }

    fn encrypt(&self, nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> Result<Vec<u8>> {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.cipher_key))
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .map_err(|_| "Critical Error: Symmetric encryption collapsed.".into())
    }

    fn decrypt(&self, nonce: &[u8; NONCE_BYTES], ciphertext: &[u8]) -> Result<Vec<u8>> {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.cipher_key))
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| INTEGRITY_FAILURE.into())
    }

    /// XOR is its own inverse, so this both applies and strips the header pad.
    fn mask_header(&self, header: [u8; HEADER_BYTES]) -> [u8; HEADER_BYTES] {
        std::array::from_fn(|i| header[i] ^ self.header_mask[i])
    }
}

/// Compressed before encryption, never after: ciphertext is random to within
/// any compressor's reach, so the other order saves nothing. Structured
/// payloads shrink about threefold, and since the number of pixels disturbed
/// follows the payload's size, that is a threefold cut in what embedding leaves
/// behind — the one defence here that does not rest on a contested measurement.
fn pack(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(plaintext)
        .map_err(|e| format!("could not compress the payload: {e}"))?;
    let deflated = encoder
        .finish()
        .map_err(|e| format!("could not compress the payload: {e}"))?;

    // Already-compressed input comes back slightly larger, so it is kept as it
    // arrived rather than paying to store it worse.
    let (tag, body) = if deflated.len() < plaintext.len() {
        (DEFLATED, deflated.as_slice())
    } else {
        (STORED, plaintext)
    };

    let mut packed = Vec::with_capacity(1 + body.len());
    packed.push(tag);
    packed.extend_from_slice(body);
    Ok(packed)
}

fn unpack(packed: &[u8]) -> Result<Vec<u8>> {
    let Some((&tag, body)) = packed.split_first() else {
        return Err("decrypted payload is empty".into());
    };

    match tag {
        STORED => Ok(body.to_vec()),
        DEFLATED => {
            let mut plaintext = Vec::new();
            ZlibDecoder::new(body)
                .read_to_end(&mut plaintext)
                .map_err(|e| format!("could not decompress the payload: {e}"))?;
            Ok(plaintext)
        }
        other => Err(format!("payload claims an unknown encoding {other}").into()),
    }
}

fn subkey(master: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(master);
    hasher.update(domain);
    hasher.finalize().into()
}

struct PixelSlot {
    x: u32,
    y: u32,
    channel: usize,
}

/// Widened before multiplying: `u32` would wrap past roughly 1.4 gigapixels.
fn slot_count(width: u32, height: u32) -> usize {
    width as usize * height as usize * CHANNELS
}

/// Every entry point into a carrier calls this before touching a slot. The
/// header occupies a fixed span at the head of both paths, and the indexing
/// below it is unchecked — `split_off` and the header slices would panic on a
/// carrier too small to hold one, so no caller may skip this.
fn check_room_for_header(width: u32, height: u32) -> Result<()> {
    if slot_count(width, height) < SALT_BITS + NONCE_BITS + HEADER_BITS {
        return Err("FATAL ERROR: Carrier is too small to hold a stego header.".into());
    }
    Ok(())
}

/// Every slot, in the fixed order anyone can reproduce. Its first `SALT_BITS`
/// hold the salt; `payload_path` re-scatters the rest under the derived key.
fn public_path(width: u32, height: u32) -> Vec<PixelSlot> {
    let mut slots = Vec::with_capacity(slot_count(width, height));
    for y in 0..height {
        for x in 0..width {
            for channel in 0..CHANNELS {
                slots.push(PixelSlot { x, y, channel });
            }
        }
    }

    slots.shuffle(&mut ChaCha20Rng::from_seed(PUBLIC_SEED));
    slots
}

/// Encoder and decoder must walk the payload in the same order, so both derive
/// it here from the same key.
fn payload_path(mut slots: Vec<PixelSlot>, shuffle_key: [u8; 32]) -> Vec<PixelSlot> {
    slots.shuffle(&mut ChaCha20Rng::from_seed(shuffle_key));
    slots
}

fn to_bits(bits: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
}

fn from_bits(bits: &[u8]) -> Vec<u8> {
    bits.as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |byte, (i, bit)| byte | (bit << (7 - i)))
        })
        .collect()
}

/// LSB matching: nudge the channel by one rather than forcing its low bit.
/// Forcing it only ever moves 2i up and 2i+1 down, which flattens the histogram
/// pair and hands a chi-square test the answer; ±1 leaves that shape intact.
fn write_bit(channel: &mut u8, bit: u8, rng: &mut ChaCha20Rng) {
    if *channel & 1 == bit {
        return;
    }

    *channel = match *channel {
        0 => 1,
        255 => 254,
        value if rng.next_u32() & 1 == 0 => value - 1,
        value => value + 1,
    };
}

fn read_bit(buffer: &RgbaImage) -> impl Fn(&PixelSlot) -> u8 + '_ {
    |slot| buffer.get_pixel(slot.x, slot.y).0[slot.channel] & 1
}

/// Slots left untouched past the payload: unlike overwriting every low bit in
/// the frame, this keeps the carrier's own statistics everywhere it can.
fn embed(
    buffer: &mut RgbaImage,
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    keys: &Keys,
) -> Result<()> {
    let (width, height) = buffer.dimensions();
    check_room_for_header(width, height)?;

    let mut salt_slots = public_path(width, height);
    let body_slots = payload_path(salt_slots.split_off(SALT_BITS), keys.shuffle_key);

    let mut body = Vec::with_capacity(NONCE_BITS + HEADER_BITS + ciphertext.len() * 8);
    to_bits(&mut body, nonce);
    let mut header = [0u8; HEADER_BYTES];
    header[0] = FORMAT_VERSION;
    header[1..].copy_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    to_bits(&mut body, &keys.mask_header(header));
    to_bits(&mut body, ciphertext);

    if body.len() > body_slots.len() {
        return Err(too_small(body.len(), body_slots.len()));
    }

    let mut salt_bits = Vec::with_capacity(SALT_BITS);
    to_bits(&mut salt_bits, salt);

    let mut rng = ChaCha20Rng::from_entropy();
    let written = salt_slots
        .iter()
        .zip(salt_bits)
        .chain(body_slots.iter().zip(body));
    for (slot, bit) in written {
        write_bit(
            &mut buffer.get_pixel_mut(slot.x, slot.y).0[slot.channel],
            bit,
            &mut rng,
        );
    }

    Ok(())
}

/// The salt sits at fixed slots, so it can be read before any key exists.
fn read_salt(buffer: &RgbaImage) -> Result<[u8; SALT_BYTES]> {
    let (width, height) = buffer.dimensions();
    check_room_for_header(width, height)?;

    let path = public_path(width, height);
    let bits: Vec<u8> = path[..SALT_BITS].iter().map(read_bit(buffer)).collect();
    Ok(from_bits(&bits)
        .try_into()
        .expect("SALT_BITS is 8 * SALT_BYTES"))
}

/// Reads the nonce and length, then exactly that much ciphertext — whatever
/// lies past the payload must never reach the cipher.
fn extract(buffer: &RgbaImage, keys: &Keys) -> Result<([u8; NONCE_BYTES], Vec<u8>)> {
    let (width, height) = buffer.dimensions();
    check_room_for_header(width, height)?;

    let mut slots = public_path(width, height);
    let slots = payload_path(slots.split_off(SALT_BITS), keys.shuffle_key);
    let read = read_bit(buffer);

    let nonce_bits: Vec<u8> = slots[..NONCE_BITS].iter().map(&read).collect();
    let nonce: [u8; NONCE_BYTES] = from_bits(&nonce_bits)
        .try_into()
        .expect("NONCE_BITS is 8 * NONCE_BYTES");

    let header_bits: Vec<u8> = slots[NONCE_BITS..NONCE_BITS + HEADER_BITS]
        .iter()
        .map(&read)
        .collect();
    let header = keys.mask_header(
        from_bits(&header_bits)
            .try_into()
            .expect("HEADER_BITS is 8 * HEADER_BYTES"),
    );
    let length = u32::from_be_bytes(
        header[1..]
            .try_into()
            .expect("HEADER_BYTES is one version byte plus four length bytes"),
    ) as usize;

    // A wrong password turns the whole header into noise, so bound the length
    // before using it to index the slot path — and before trusting the version
    // byte beside it, which is noise under exactly the same circumstances.
    // Multiplied through `checked_mul` because a `u32` length scaled to bits
    // overflows a 32-bit `usize`, and a wrapped product could slip past the
    // comparison below and panic at the slice.
    let body = NONCE_BITS + HEADER_BITS;
    let Some(payload_bits) = length.checked_mul(8) else {
        return Err(INTEGRITY_FAILURE.into());
    };
    if length < GCM_TAG_LEN || payload_bits > slots.len() - body {
        return Err(INTEGRITY_FAILURE.into());
    }

    // Past that check the header is almost certainly genuine rather than noise
    // that happened to land in range, so an unrecognised version is worth
    // naming: "written by another build" is something the user can act on,
    // where "wrong password" would send them looking in the wrong place.
    if header[0] != FORMAT_VERSION {
        return Err(format!(
            "this carrier is stego format v{}, and this build reads v{FORMAT_VERSION}",
            header[0]
        )
        .into());
    }

    let bits: Vec<u8> = slots[body..body + payload_bits].iter().map(&read).collect();
    Ok((nonce, from_bits(&bits)))
}

/// Bit depth and colour type, straight out of the PNG header. `image::open`
/// expands palettes and odd depths while decoding, so what the carrier is
/// actually stored as cannot be recovered from the decoded image.
fn png_format(head: &[u8]) -> Option<(u8, u8)> {
    (head.len() >= 26 && head[..8] == *b"\x89PNG\r\n\x1a\n").then(|| (head[24], head[25]))
}

fn is_png(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[..8] == *b"\x89PNG\r\n\x1a\n"
}

/// Each chunk's four-byte type alongside its whole on-disk span — length, type,
/// data and CRC — so a chunk can be copied over without recomputing anything.
fn png_chunks(png: &[u8]) -> Vec<(&[u8], &[u8])> {
    let mut chunks = Vec::new();
    let mut pos = 8;

    while pos + 12 <= png.len() {
        let length = u32::from_be_bytes(png[pos..pos + 4].try_into().unwrap()) as usize;
        let Some(end) = pos.checked_add(12 + length).filter(|e| *e <= png.len()) else {
            break;
        };

        let kind = &png[pos + 4..pos + 8];
        chunks.push((kind, &png[pos..end]));
        if kind == b"IEND" {
            break;
        }
        pos = end;
    }

    chunks
}

fn preserved_metadata(source: &[u8]) -> Vec<u8> {
    if !is_png(source) {
        return Vec::new();
    }

    png_chunks(source)
        .into_iter()
        .filter(|(kind, _)| PRESERVED_CHUNKS.contains(kind))
        .flat_map(|(_, raw)| raw.iter().copied())
        .collect()
}

/// Straight after IHDR, which is a legal position for every chunk in the
/// allowlist — the colour-space ones have to precede IDAT, and the rest may sit
/// anywhere between the header and the end.
fn splice_after_ihdr(png: Vec<u8>, metadata: &[u8]) -> Vec<u8> {
    if metadata.is_empty() || png.len() < AFTER_IHDR || &png[12..16] != b"IHDR" {
        return png;
    }

    let mut spliced = Vec::with_capacity(png.len() + metadata.len());
    spliced.extend_from_slice(&png[..AFTER_IHDR]);
    spliced.extend_from_slice(metadata);
    spliced.extend_from_slice(&png[AFTER_IHDR..]);
    spliced
}

/// Anything but 8-bit RGB has to be converted before a bit can be hidden in it,
/// and the conversion is louder than the embedding it enables.
fn warn_if_poor_carrier(head: &[u8]) {
    let Some((depth, colour)) = png_format(head) else {
        return;
    };
    let tell = match (colour, depth) {
        (3, _) => "a palette's handful of colours turns into hundreds",
        (0 | 4, _) => "a greyscale image stops satisfying R == G == B",
        (_, 8) => return,
        _ => "every sample is requantised to 8 bits",
    };

    eprintln!(
        "⚠️  This carrier is not 8-bit RGB, so embedding has to convert it. The \
         output will be much larger than the original, will declare a different \
         colour type in its header, and {tell} — each of which gives it away \
         without any statistics. Prefer a grainy 8-bit RGB photograph."
    );
}

fn too_small(needed_bits: usize, available_bits: usize) -> Box<dyn Error> {
    let required_pixels = (needed_bits + SALT_BITS).div_ceil(CHANNELS);
    let target_dimension = (required_pixels as f64).sqrt().ceil() as u32;

    format!(
        "FATAL ERROR: The selected PNG is too small for this payload.\n   \
         Available space: {available_bits} bits | Required: {needed_bits} bits\n   \
         💡 Suggested minimum square PNG dimensions: {target_dimension}x{target_dimension} px\n   \
         Estimated raw storage needed: {} bytes",
        required_pixels * 4
    )
    .into()
}

/// A password in `argv` is readable by every other process on the machine and
/// lands in shell history, so the flag is the last resort rather than the first.
///
/// The returned copy is wiped when dropped. Note what that cannot reach: the
/// flag's own string in `argv`, and the environment block the variable came
/// from, both of which the kernel keeps for as long as the process lives. Only
/// the prompt leaves nothing behind elsewhere.
fn resolve_password(flag: Option<&String>) -> Result<Zeroizing<String>> {
    if let Some(password) = flag {
        eprintln!(
            "⚠️  --password is visible to `ps` and saved in your shell history; \
             prefer ${PASSWORD_ENV} or the prompt."
        );
        return Ok(Zeroizing::new(password.clone()));
    }

    if let Ok(password) = std::env::var(PASSWORD_ENV) {
        return Ok(Zeroizing::new(password));
    }

    rpassword::prompt_password("Password: ")
        .map(Zeroizing::new)
        .map_err(|e| format!("could not read a password from the terminal: {e}").into())
}

/// True only when both paths resolve to one existing file, so symlinks and
/// `./photo.png` against `photo.png` are caught. An output that does not exist
/// yet cannot be overwriting anything, and `canonicalize` failing on it is
/// exactly the signal that it is new.
fn same_file(a: &str, b: &str) -> bool {
    matches!(
        (fs::canonicalize(a), fs::canonicalize(b)),
        (Ok(a), Ok(b)) if a == b
    )
}

fn encode(input: &str, output: &str, password: Option<&String>, text_file: &str) -> Result<()> {
    // Every path is read and checked before a password is asked for or a key
    // derived: Argon2 takes long enough that spending it on a mistyped filename
    // is its own small insult, and nobody should type a password to be told the
    // carrier does not exist.
    let plaintext = Zeroizing::new(
        fs::read(text_file)
            .map_err(|e| format!("Failed to read the secret plaintext file '{text_file}': {e}"))?,
    );

    // Refused rather than handled: writing the result over its own source
    // destroys a carrier you may not be able to take again.
    if same_file(input, output) {
        return Err("input and output point to the same file".into());
    }

    let source_bytes =
        fs::read(input).map_err(|e| format!("Failed to open input PNG image '{input}': {e}"))?;
    let source = image::load_from_memory(&source_bytes)
        .map_err(|e| format!("Failed to decode input PNG image '{input}': {e}"))?;
    warn_if_poor_carrier(&source_bytes);
    let had_alpha = source.color().has_alpha();
    let mut buffer = source.to_rgba8();

    let password = resolve_password(password)?;

    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let keys = Keys::derive(&password, &salt)?;
    let ciphertext = keys.encrypt(&nonce, &Zeroizing::new(pack(&plaintext)?))?;

    embed(&mut buffer, &salt, &nonce, &ciphertext, &keys)?;

    // Saved back under the carrier's own colour type. Alpha is never written to,
    // so dropping a channel the input did not have loses nothing — and a PNG
    // that gained one announces in its header that something processed it.
    let stego = if had_alpha {
        DynamicImage::ImageRgba8(buffer)
    } else {
        DynamicImage::ImageRgb8(DynamicImage::ImageRgba8(buffer).to_rgb8())
    };
    // Encoded to memory so the carrier's own chunks can be put back around it.
    // Always PNG, whatever the output is named: no lossy format would keep the
    // low bits the message lives in.
    let mut encoded = Vec::new();
    stego
        .write_to(
            &mut std::io::Cursor::new(&mut encoded),
            image::ImageFormat::Png,
        )
        .map_err(|e| format!("Failed to encode stego PNG: {e}"))?;

    fs::write(
        output,
        splice_after_ihdr(encoded, &preserved_metadata(&source_bytes)),
    )
    .map_err(|e| format!("Failed to save stego PNG file '{output}': {e}"))?;

    eprintln!("🔒 Encoded! Message encrypted, scrambled and bound safely inside '{output}'.");
    Ok(())
}

/// Everything that needs no password: opening the image, and reading the salt
/// from its fixed public slots. Split out so a bad path or an unusable carrier
/// is reported *before* anyone is asked to type a password for it.
fn open_carrier(input: &str) -> Result<(RgbaImage, [u8; SALT_BYTES])> {
    let buffer = image::open(input)
        .map_err(|e| format!("Failed to open target PNG container '{input}': {e}"))?
        .to_rgba8();

    let salt = read_salt(&buffer)?;
    Ok((buffer, salt))
}

fn recover(
    buffer: &RgbaImage,
    salt: &[u8; SALT_BYTES],
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let keys = Keys::derive(password, salt)?;
    let (nonce, ciphertext) = extract(buffer, &keys)?;
    let decrypted = Zeroizing::new(keys.decrypt(&nonce, &ciphertext)?);
    Ok(Zeroizing::new(unpack(&decrypted)?))
}

/// Reads the message back and says whether it survived, without putting it on
/// stdout — a backup wants checking far more often than it wants opening, and
/// an untested backup is not a backup.
fn verify(input: &str, password: Option<&String>, text_file: Option<&String>) -> Result<()> {
    let (buffer, salt) = open_carrier(input)?;

    // Read ahead of the prompt as well, so a mistyped comparison path does not
    // cost a password either.
    let expected = text_file
        .map(|path| {
            fs::read(path)
                .map(Zeroizing::new)
                .map_err(|e| format!("Failed to read the file to compare against '{path}': {e}"))
        })
        .transpose()?;

    let password = resolve_password(password)?;
    let recovered = recover(&buffer, &salt, &password)?;

    println!(
        "✅ Readable: {} bytes recovered from '{input}'.",
        recovered.len()
    );
    println!("   SHA3-256: {:x}", Sha3_256::digest(recovered.as_slice()));

    if let (Some(path), Some(expected)) = (text_file, expected) {
        if recovered.as_slice() != expected.as_slice() {
            return Err(format!(
                "recovered {} bytes but '{path}' holds {} — they do not match",
                recovered.len(),
                expected.len()
            )
            .into());
        }
        println!("   Identical to '{path}'.");
    }

    Ok(())
}

fn decode(input: &str, password: Option<&String>) -> Result<()> {
    let (buffer, salt) = open_carrier(input)?;
    let password = resolve_password(password)?;
    let plaintext = recover(&buffer, &salt, &password)?;

    eprintln!("🔓 Decoded!");

    // Written as raw bytes, not printed: the payload is whatever file was
    // hidden, so it must come back byte for byte, newlines and all.
    let mut stdout = std::io::stdout();
    stdout.write_all(plaintext.as_slice())?;
    stdout.flush()?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let outcome = match &cli.command {
        Commands::Encode {
            input,
            output,
            password,
            text_file,
        } => encode(input, output, password.as_ref(), text_file),
        Commands::Decode { input, password } => decode(input, password.as_ref()),
        Commands::Verify {
            input,
            password,
            text_file,
        } => verify(input, password.as_ref(), text_file.as_ref()),
    };

    if let Err(err) = outcome {
        eprintln!("❌ {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    const SALT: [u8; SALT_BYTES] = [7; SALT_BYTES];
    const NONCE: [u8; NONCE_BYTES] = [9; NONCE_BYTES];

    /// Argon2 is deliberately slow, and the carrier tests below exercise
    /// embedding rather than the KDF, so they skip straight to the subkeys.
    fn keys(seed: u8) -> Keys {
        Keys::from_master(&[seed; 32])
    }

    /// A gradient rather than a flat fill: against a flat carrier, a bug that
    /// returned the carrier's own bits could pass for a correct answer.
    fn carrier(width: u32, height: u32) -> RgbaImage {
        RgbaImage::from_fn(width, height, |x, y| {
            Rgba([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8, 255])
        })
    }

    fn capacity(width: u32, height: u32) -> usize {
        (slot_count(width, height) - SALT_BITS - NONCE_BITS - HEADER_BITS) / 8
    }

    #[test]
    fn round_trips_a_payload() {
        let keys = keys(1);
        let ciphertext = keys.encrypt(&NONCE, b"attack at dawn").unwrap();

        let mut buffer = carrier(64, 64);
        embed(&mut buffer, &SALT, &NONCE, &ciphertext, &keys).unwrap();

        assert_eq!(read_salt(&buffer).unwrap(), SALT);
        let (nonce, recovered) = extract(&buffer, &keys).unwrap();
        assert_eq!(nonce, NONCE);
        assert_eq!(recovered, ciphertext);
        assert_eq!(keys.decrypt(&nonce, &recovered).unwrap(), b"attack at dawn");
    }

    /// The regression this guards: decode once read every slot in the carrier,
    /// handing the fill past the payload to AES-GCM along with the ciphertext.
    #[test]
    fn fill_past_the_payload_stays_out_of_it() {
        let keys = keys(2);
        let ciphertext = keys.encrypt(&NONCE, b"short").unwrap();

        let mut buffer = carrier(128, 128);
        embed(&mut buffer, &SALT, &NONCE, &ciphertext, &keys).unwrap();

        let (nonce, recovered) = extract(&buffer, &keys).unwrap();
        assert_eq!(recovered.len(), ciphertext.len());
        assert!(keys.decrypt(&nonce, &recovered).is_ok());
    }

    #[test]
    fn fills_the_carrier_to_the_last_slot() {
        let keys = keys(3);
        let plaintext = vec![b'z'; capacity(32, 32) - GCM_TAG_LEN];
        let ciphertext = keys.encrypt(&NONCE, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), capacity(32, 32));

        let mut buffer = carrier(32, 32);
        embed(&mut buffer, &SALT, &NONCE, &ciphertext, &keys).unwrap();

        let (nonce, recovered) = extract(&buffer, &keys).unwrap();
        assert_eq!(keys.decrypt(&nonce, &recovered).unwrap(), plaintext);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let right = keys(4);
        let ciphertext = right.encrypt(&NONCE, b"secret").unwrap();
        let mut buffer = carrier(64, 64);
        embed(&mut buffer, &SALT, &NONCE, &ciphertext, &right).unwrap();

        // Rejected at the length header, or — if the garbage length happens to
        // be in range — at the GCM tag. Either way nothing is handed back.
        let wrong = keys(5);
        match extract(&buffer, &wrong) {
            Err(_) => {}
            Ok((nonce, ciphertext)) => assert!(wrong.decrypt(&nonce, &ciphertext).is_err()),
        }
    }

    #[test]
    fn payload_larger_than_the_carrier_is_refused() {
        let keys = keys(6);
        let mut buffer = carrier(16, 16);

        let oversized = vec![0u8; slot_count(16, 16) / 8];
        assert!(embed(&mut buffer, &SALT, &NONCE, &oversized, &keys).is_err());
    }

    #[test]
    fn only_the_low_bits_of_rgb_are_touched() {
        let keys = keys(7);
        let ciphertext = keys.encrypt(&NONCE, b"x").unwrap();

        let original = carrier(32, 32);
        let mut buffer = original.clone();
        embed(&mut buffer, &SALT, &NONCE, &ciphertext, &keys).unwrap();

        for (before, after) in original.pixels().zip(buffer.pixels()) {
            for channel in 0..CHANNELS {
                let (before, after) = (before.0[channel] as i16, after.0[channel] as i16);
                assert!(
                    (before - after).abs() <= 1,
                    "a channel moved by more than one"
                );
            }
            assert_eq!(before.0[3], after.0[3], "alpha moved");
        }
    }

    /// Every carrier entry point indexes a fixed header span without checking
    /// again, so each has to refuse a carrier too small to hold one — an error,
    /// never a panic. `extract` used to rely on `read_salt` having been called
    /// first, which is an ordering nothing enforced.
    #[test]
    fn a_carrier_too_small_for_a_header_is_refused() {
        let keys = keys(9);
        let mut tiny = carrier(4, 4); // 48 slots against the 264 a header needs
        assert!(slot_count(4, 4) < SALT_BITS + NONCE_BITS + HEADER_BITS);

        assert!(embed(&mut tiny, &SALT, &NONCE, b"anything", &keys).is_err());
        assert!(read_salt(&tiny).is_err());
        assert!(extract(&tiny, &keys).is_err());
    }

    /// Writing over the carrier is refused, so the comparison has to see through
    /// however a path is spelled — otherwise `./photo.png` against `photo.png`
    /// slips past and destroys the original.
    #[test]
    fn the_carrier_is_recognised_however_it_is_spelled() {
        assert!(same_file("src/main.rs", "./src/main.rs"));
        assert!(!same_file("src/main.rs", "Cargo.toml"));

        // An output that does not exist yet cannot be the carrier.
        assert!(!same_file("src/main.rs", "src/main.rs.nonexistent"));
    }

    /// Matching must never run a channel past the ends of the byte.
    #[test]
    fn saturated_channels_stay_in_range() {
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        for value in [0u8, 255] {
            for bit in [0u8, 1] {
                let mut channel = value;
                write_bit(&mut channel, bit, &mut rng);
                assert_eq!(channel & 1, bit, "{value} did not take bit {bit}");
                assert!(channel.abs_diff(value) <= 1, "{value} moved too far");
            }
        }
    }

    /// The flaw that made two images under one password XOR to their plaintexts:
    /// a nonce that was a pure function of the password.
    #[test]
    fn salt_and_nonce_are_random_per_image() {
        let mut first = [0u8; SALT_BYTES];
        let mut second = [0u8; SALT_BYTES];
        OsRng.fill_bytes(&mut first);
        OsRng.fill_bytes(&mut second);
        assert_ne!(first, second);
    }

    #[test]
    fn png_format_reads_the_header() {
        let mut head = [0u8; 26];
        head[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        head[24] = 4; // bit depth
        head[25] = 3; // colour type: indexed
        assert_eq!(png_format(&head), Some((4, 3)));

        head[0] = b'X';
        assert_eq!(png_format(&head), None, "a non-PNG must not be parsed");
        assert_eq!(png_format(&[]), None, "a short read must not panic");
    }

    /// Builds a PNG-shaped byte stream: signature, IHDR, then whatever follows.
    fn png_with(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        for (kind, data) in std::iter::once((b"IHDR", [0u8; 13].as_slice()))
            .chain(chunks.iter().map(|(kind, data)| (*kind, *data)))
        {
            png.extend_from_slice(&(data.len() as u32).to_be_bytes());
            png.extend_from_slice(kind);
            png.extend_from_slice(data);
            png.extend_from_slice(&[0; 4]); // CRC: never checked, only copied
        }
        png
    }

    #[test]
    fn png_chunks_walks_the_stream_and_stops_at_iend() {
        let png = png_with(&[(b"pHYs", &[1, 2, 3]), (b"IDAT", &[9; 20]), (b"IEND", &[])]);
        let kinds: Vec<_> = png_chunks(&png).iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, [b"IHDR", b"pHYs", b"IDAT", b"IEND"]);
    }

    #[test]
    fn png_chunks_survives_a_truncated_stream() {
        let mut png = png_with(&[(b"pHYs", &[1, 2, 3])]);
        png.truncate(png.len() - 5);
        assert_eq!(
            png_chunks(&png).len(),
            1,
            "the partial chunk must be dropped"
        );

        let mut lying = png_with(&[(b"pHYs", &[1, 2, 3])]);
        lying[33..37].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            png_chunks(&lying).len(),
            1,
            "an absurd length must not panic"
        );
    }

    #[test]
    fn metadata_keeps_the_allowlist_and_drops_the_rest() {
        let png = png_with(&[
            (b"sRGB", &[0]),
            (b"PLTE", &[1; 9]),    // describes a palette the output will not have
            (b"sBIT", &[8, 8, 8]), // would call the low bits insignificant
            (b"eXIf", &[7; 6]),
            (b"IDAT", &[9; 20]),
            (b"IEND", &[]),
        ]);

        let kept = preserved_metadata(&png);
        let kinds: Vec<_> = png_chunks(&[b"\x89PNG\r\n\x1a\n".to_vec(), kept.clone()].concat())
            .iter()
            .map(|(k, _)| std::str::from_utf8(k).unwrap().to_string())
            .collect();
        assert_eq!(kinds, ["sRGB", "eXIf"]);

        assert!(preserved_metadata(b"not a png at all").is_empty());
    }

    #[test]
    fn splice_puts_metadata_directly_after_ihdr() {
        let png = png_with(&[(b"IDAT", &[9; 20]), (b"IEND", &[])]);
        let metadata = preserved_metadata(&png_with(&[(b"pHYs", &[1; 9]), (b"IEND", &[])]));

        let spliced = splice_after_ihdr(png.clone(), &metadata);
        let kinds: Vec<_> = png_chunks(&spliced).iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, [b"IHDR", b"pHYs", b"IDAT", b"IEND"]);

        assert_eq!(
            splice_after_ihdr(png.clone(), &[]),
            png,
            "nothing to add, nothing changed"
        );
        assert_eq!(
            splice_after_ihdr(vec![0; 4], &metadata),
            vec![0; 4],
            "too short to splice"
        );
    }

    #[test]
    fn packing_round_trips_and_picks_the_smaller_form() {
        let text = b"xyzzy ".repeat(500);
        let packed = pack(&text).unwrap();
        assert_eq!(packed[0], DEFLATED);
        assert!(packed.len() < text.len() / 4, "repetitive text must shrink");
        assert_eq!(unpack(&packed).unwrap(), text);

        // Incompressible input: deflate would add bytes, so it is stored raw.
        let mut noise = vec![0u8; 4096];
        OsRng.fill_bytes(&mut noise);
        let packed = pack(&noise).unwrap();
        assert_eq!(packed[0], STORED);
        assert_eq!(packed.len(), noise.len() + 1);
        assert_eq!(unpack(&packed).unwrap(), noise);

        assert_eq!(unpack(&pack(b"").unwrap()).unwrap(), b"");
    }

    #[test]
    fn unpack_rejects_what_it_cannot_read() {
        assert!(unpack(&[]).is_err(), "an empty payload has no tag");
        assert!(unpack(&[7, 1, 2, 3]).is_err(), "unknown encoding tag");
        assert!(
            unpack(&[DEFLATED, 0, 1, 2]).is_err(),
            "not a deflate stream"
        );
    }

    /// A carrier written by a different build must say so rather than hide
    /// behind the generic integrity failure — the whole point of the version
    /// byte. Forged by masking a bumped version into an otherwise valid header.
    #[test]
    fn an_unknown_format_version_is_named() {
        let keys = keys(8);
        let ciphertext = keys.encrypt(&NONCE, b"from the future").unwrap();

        let mut buffer = carrier(64, 64);
        embed(&mut buffer, &SALT, &NONCE, &ciphertext, &keys).unwrap();

        // Rewrite just the version byte's slots, leaving the length intact so
        // the bounds check passes and the version is the thing that fails.
        let (width, height) = buffer.dimensions();
        let mut slots = public_path(width, height);
        let slots = payload_path(slots.split_off(SALT_BITS), keys.shuffle_key);
        let mut header = [0u8; HEADER_BYTES];
        header[0] = FORMAT_VERSION + 1;
        header[1..].copy_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        let mut bits = Vec::new();
        to_bits(&mut bits, &keys.mask_header(header));

        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        for (slot, bit) in slots[NONCE_BITS..NONCE_BITS + HEADER_BITS].iter().zip(bits) {
            write_bit(
                &mut buffer.get_pixel_mut(slot.x, slot.y).0[slot.channel],
                bit,
                &mut rng,
            );
        }

        let err = extract(&buffer, &keys).unwrap_err().to_string();
        assert!(err.contains("v2"), "should name the version it found: {err}");
        assert!(!err.contains("Integrity"), "should not hide behind it: {err}");
    }

    /// Compile-time only: it cannot observe freed memory, but it does fail the
    /// build if anyone drops the derive, which is the realistic way this
    /// protection would be lost.
    #[test]
    fn keys_are_wiped_when_dropped() {
        fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        requires_zeroize_on_drop::<Keys>();
    }

    /// One real derivation, to prove the salt actually reaches Argon2.
    #[test]
    fn the_salt_changes_the_derived_keys() {
        let a = Keys::derive("password", &[1; SALT_BYTES]).unwrap();
        let b = Keys::derive("password", &[2; SALT_BYTES]).unwrap();
        assert_ne!(a.cipher_key, b.cipher_key);
        assert_ne!(a.shuffle_key, b.shuffle_key);
    }
}
