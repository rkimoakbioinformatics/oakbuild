use base64::Engine;
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{
    Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::signature::{SignatureEncoding, Signer as RsaSignerTrait, Verifier as RsaVerifierTrait};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"OAKBUILD";
pub const FOOTER_VERSION: u8 = 2;
pub const FOOTER_FLAG_SIGNED: u8 = 0x01;
pub const TRAILER_LEN: u64 = 56;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    None,
    Ed25519,
    RsaPkcs1v15Sha256,
}

impl SignatureAlgorithm {
    fn to_byte(self) -> u8 {
        match self {
            SignatureAlgorithm::None => 0,
            SignatureAlgorithm::Ed25519 => 1,
            SignatureAlgorithm::RsaPkcs1v15Sha256 => 2,
        }
    }

    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(SignatureAlgorithm::None),
            1 => Some(SignatureAlgorithm::Ed25519),
            2 => Some(SignatureAlgorithm::RsaPkcs1v15Sha256),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SignatureAlgorithm::None => "none",
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::RsaPkcs1v15Sha256 => "rsa-pkcs1v15-sha256",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Footer {
    pub version: u8,
    pub flags: u8,
    pub algorithm: SignatureAlgorithm,
    pub payload_len: u64,
    pub sha256: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer: String,
    pub signed_at: String,
    pub legacy_payload_signature: bool,
}

impl Footer {
    pub fn is_signed(&self) -> bool {
        self.flags & FOOTER_FLAG_SIGNED != 0
    }
}

#[derive(Debug)]
pub enum VerificationStatus {
    SignedValid,
    UnsignedValid,
    HashMismatch,
    SignatureInvalid,
}

#[derive(Debug)]
pub enum SigningMaterial {
    Ed25519 {
        signing_key: Ed25519SigningKey,
        public_key: [u8; 32],
    },
    Rsa {
        signing_key: RsaPrivateKey,
        public_key_der: Vec<u8>,
    },
}

pub struct SigningRequest<'a> {
    pub material: &'a SigningMaterial,
    pub signer: &'a str,
    pub signed_at: &'a str,
}

impl SigningMaterial {
    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            SigningMaterial::Ed25519 { .. } => SignatureAlgorithm::Ed25519,
            SigningMaterial::Rsa { .. } => SignatureAlgorithm::RsaPkcs1v15Sha256,
        }
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            SigningMaterial::Ed25519 { public_key, .. } => public_key.to_vec(),
            SigningMaterial::Rsa { public_key_der, .. } => public_key_der.clone(),
        }
    }

    fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SigningMaterial::Ed25519 { signing_key, .. } => {
                signing_key.sign(message).to_bytes().to_vec()
            }
            SigningMaterial::Rsa { signing_key, .. } => {
                let signer = RsaSigningKey::<Sha256>::new(signing_key.clone());
                let sig: RsaSignature = RsaSignerTrait::sign(&signer, message);
                sig.to_bytes().to_vec()
            }
        }
    }
}

pub fn read_all_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn encode_metadata(
    public_key: &[u8],
    signature: &[u8],
    signer: &str,
    signed_at: &str,
) -> io::Result<Vec<u8>> {
    let public_key_len = u32::try_from(public_key.len()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "public key is too large to encode in footer metadata",
        )
    })?;
    let signature_len = u32::try_from(signature.len()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "signature is too large to encode in footer metadata",
        )
    })?;
    let signer_len = u32::try_from(signer.len()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "signer string is too large to encode in footer metadata",
        )
    })?;
    let signed_at_len = u32::try_from(signed_at.len()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "signed_at string is too large to encode in footer metadata",
        )
    })?;

    let mut out = Vec::with_capacity(
        16 + public_key.len() + signature.len() + signer.len() + signed_at.len(),
    );
    out.extend_from_slice(&public_key_len.to_le_bytes());
    out.extend_from_slice(&signature_len.to_le_bytes());
    out.extend_from_slice(&signer_len.to_le_bytes());
    out.extend_from_slice(&signed_at_len.to_le_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(signature);
    out.extend_from_slice(signer.as_bytes());
    out.extend_from_slice(signed_at.as_bytes());
    Ok(out)
}

#[derive(Debug)]
struct DecodedMetadata {
    public_key: Vec<u8>,
    signature: Vec<u8>,
    signer: String,
    signed_at: String,
    legacy_payload_signature: bool,
}

fn decode_metadata(metadata: &[u8]) -> Option<DecodedMetadata> {
    if metadata.len() < 8 {
        return None;
    }

    let public_key_len = u32::from_le_bytes(metadata[0..4].try_into().ok()?) as usize;
    let signature_len = u32::from_le_bytes(metadata[4..8].try_into().ok()?) as usize;
    let legacy_len = 8usize
        .checked_add(public_key_len)?
        .checked_add(signature_len)?;

    if metadata.len() == legacy_len {
        let public_key_start = 8;
        let signature_start = public_key_start + public_key_len;
        let public_key = metadata[public_key_start..signature_start].to_vec();
        let signature = metadata[signature_start..].to_vec();
        return Some(DecodedMetadata {
            public_key,
            signature,
            signer: String::new(),
            signed_at: String::new(),
            legacy_payload_signature: true,
        });
    }

    if metadata.len() < 16 {
        return None;
    }

    let signer_len = u32::from_le_bytes(metadata[8..12].try_into().ok()?) as usize;
    let signed_at_len = u32::from_le_bytes(metadata[12..16].try_into().ok()?) as usize;
    let expected_len = 16usize
        .checked_add(public_key_len)?
        .checked_add(signature_len)?
        .checked_add(signer_len)?
        .checked_add(signed_at_len)?;
    if metadata.len() != expected_len {
        return None;
    }

    let public_key_start = 16;
    let signature_start = public_key_start + public_key_len;
    let signer_start = signature_start + signature_len;
    let signed_at_start = signer_start + signer_len;

    let public_key = metadata[public_key_start..signature_start].to_vec();
    let signature = metadata[signature_start..signer_start].to_vec();
    let signer = std::str::from_utf8(&metadata[signer_start..signed_at_start])
        .ok()?
        .to_string();
    let signed_at = std::str::from_utf8(&metadata[signed_at_start..])
        .ok()?
        .to_string();

    Some(DecodedMetadata {
        public_key,
        signature,
        signer,
        signed_at,
        legacy_payload_signature: false,
    })
}

fn build_signing_message(payload_sha256: &[u8; 32], signer: &str, signed_at: &str) -> Vec<u8> {
    let signer_bytes = signer.as_bytes();
    let signed_at_bytes = signed_at.as_bytes();

    let mut out = Vec::with_capacity(16 + 32 + signer_bytes.len() + signed_at_bytes.len());
    out.extend_from_slice(b"OAKBUILD-SIGN-V1\0");
    out.extend_from_slice(payload_sha256);
    out.extend_from_slice(&(signer_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(signer_bytes);
    out.extend_from_slice(&(signed_at_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(signed_at_bytes);
    out
}

fn trailer_to_bytes(footer: &Footer, metadata_len: u32) -> [u8; TRAILER_LEN as usize] {
    let mut out = [0u8; TRAILER_LEN as usize];
    out[0..8].copy_from_slice(MAGIC);
    out[8] = footer.version;
    out[9] = footer.flags;
    out[10] = footer.algorithm.to_byte();
    out[11] = 0;
    out[12..20].copy_from_slice(&footer.payload_len.to_le_bytes());
    out[20..24].copy_from_slice(&metadata_len.to_le_bytes());
    out[24..56].copy_from_slice(&footer.sha256);
    out
}

fn parse_trailer(
    buf: &[u8; TRAILER_LEN as usize],
) -> Option<(u8, u8, SignatureAlgorithm, u64, u32, [u8; 32])> {
    if &buf[0..8] != MAGIC {
        return None;
    }

    let version = buf[8];
    if version != FOOTER_VERSION {
        return None;
    }

    let flags = buf[9];
    let algorithm = SignatureAlgorithm::from_byte(buf[10])?;
    let payload_len = u64::from_le_bytes(buf[12..20].try_into().ok()?);
    let metadata_len = u32::from_le_bytes(buf[20..24].try_into().ok()?);

    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&buf[24..56]);

    Some((version, flags, algorithm, payload_len, metadata_len, sha256))
}

pub fn verify_payload(payload: &[u8], footer: &Footer) -> VerificationStatus {
    let hash = sha256_bytes(payload);
    if hash != footer.sha256 {
        return VerificationStatus::HashMismatch;
    }

    if !footer.is_signed() {
        return VerificationStatus::UnsignedValid;
    }

    let signing_message = if footer.legacy_payload_signature {
        payload.to_vec()
    } else {
        build_signing_message(&footer.sha256, &footer.signer, &footer.signed_at)
    };

    match footer.algorithm {
        SignatureAlgorithm::None => VerificationStatus::SignatureInvalid,
        SignatureAlgorithm::Ed25519 => {
            if footer.public_key.len() != 32 || footer.signature.len() != 64 {
                return VerificationStatus::SignatureInvalid;
            }

            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&footer.public_key);
            let vk = match Ed25519VerifyingKey::from_bytes(&public_key) {
                Ok(vk) => vk,
                Err(_) => return VerificationStatus::SignatureInvalid,
            };

            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&footer.signature);
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            if vk.verify_strict(&signing_message, &sig).is_ok() {
                VerificationStatus::SignedValid
            } else {
                VerificationStatus::SignatureInvalid
            }
        }
        SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            let public_key = match RsaPublicKey::from_public_key_der(&footer.public_key) {
                Ok(public_key) => public_key,
                Err(_) => return VerificationStatus::SignatureInvalid,
            };

            let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);
            let sig = match RsaSignature::try_from(footer.signature.as_slice()) {
                Ok(sig) => sig,
                Err(_) => return VerificationStatus::SignatureInvalid,
            };

            if RsaVerifierTrait::verify(&verifying_key, &signing_message, &sig).is_ok() {
                VerificationStatus::SignedValid
            } else {
                VerificationStatus::SignatureInvalid
            }
        }
    }
}

pub fn try_read_footer_and_payload(path: &Path) -> io::Result<Option<(Vec<u8>, Footer)>> {
    let mut f = File::open(path)?;
    let file_len = f.metadata()?.len();
    if file_len < TRAILER_LEN {
        return Ok(None);
    }

    f.seek(SeekFrom::End(-(TRAILER_LEN as i64)))?;
    let mut trailer_buf = [0u8; TRAILER_LEN as usize];
    f.read_exact(&mut trailer_buf)?;

    let Some((version, flags, algorithm, payload_len, metadata_len, sha256)) =
        parse_trailer(&trailer_buf)
    else {
        return Ok(None);
    };

    let metadata_len_u64 = metadata_len as u64;
    if file_len < TRAILER_LEN + payload_len + metadata_len_u64 {
        return Ok(None);
    }

    let metadata_start = file_len - TRAILER_LEN - metadata_len_u64;
    let payload_start = metadata_start - payload_len;

    f.seek(SeekFrom::Start(payload_start))?;
    let mut payload = vec![0u8; payload_len as usize];
    f.read_exact(&mut payload)?;

    f.seek(SeekFrom::Start(metadata_start))?;
    let mut metadata = vec![0u8; metadata_len as usize];
    f.read_exact(&mut metadata)?;

    let signed = flags & FOOTER_FLAG_SIGNED != 0;
    let decoded_metadata = if signed {
        if algorithm == SignatureAlgorithm::None {
            return Ok(None);
        }
        let Some(decoded) = decode_metadata(&metadata) else {
            return Ok(None);
        };
        decoded
    } else {
        if algorithm != SignatureAlgorithm::None || !metadata.is_empty() {
            return Ok(None);
        }
        DecodedMetadata {
            public_key: Vec::new(),
            signature: Vec::new(),
            signer: String::new(),
            signed_at: String::new(),
            legacy_payload_signature: false,
        }
    };

    let footer = Footer {
        version,
        flags,
        algorithm,
        payload_len,
        sha256,
        public_key: decoded_metadata.public_key,
        signature: decoded_metadata.signature,
        signer: decoded_metadata.signer,
        signed_at: decoded_metadata.signed_at,
        legacy_payload_signature: decoded_metadata.legacy_payload_signature,
    };

    Ok(Some((payload, footer)))
}

pub fn write_output_from_stub(
    runner_stub: &[u8],
    out_path: &Path,
    payload: &[u8],
    signing: Option<SigningRequest<'_>>,
) -> io::Result<()> {
    let payload_hash = sha256_bytes(payload);

    let (flags, algorithm, public_key, signature, signer, signed_at) =
        if let Some(signing) = signing {
            let signing_message =
                build_signing_message(&payload_hash, signing.signer, signing.signed_at);
            (
                FOOTER_FLAG_SIGNED,
                signing.material.algorithm(),
                signing.material.public_key_bytes(),
                signing.material.sign_message(&signing_message),
                signing.signer.to_string(),
                signing.signed_at.to_string(),
            )
        } else {
            (
                0u8,
                SignatureAlgorithm::None,
                Vec::new(),
                Vec::new(),
                String::new(),
                String::new(),
            )
        };

    let metadata = if flags & FOOTER_FLAG_SIGNED != 0 {
        encode_metadata(&public_key, &signature, &signer, &signed_at)?
    } else {
        Vec::new()
    };
    let metadata_len = u32::try_from(metadata.len()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "metadata is too large to encode in footer",
        )
    })?;

    let footer = Footer {
        version: FOOTER_VERSION,
        flags,
        algorithm,
        payload_len: payload.len() as u64,
        sha256: payload_hash,
        public_key,
        signature,
        signer,
        signed_at,
        legacy_payload_signature: false,
    };

    let trailer = trailer_to_bytes(&footer, metadata_len);

    let mut out = File::create(out_path)?;
    out.write_all(runner_stub)?;
    out.write_all(payload)?;
    out.write_all(&metadata)?;
    out.write_all(&trailer)?;
    out.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(out_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(out_path, perms)?;
    }

    Ok(())
}

fn try_parse_hex_32(text: &str) -> Option<[u8; 32]> {
    let mut compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if let Some(rest) = compact.strip_prefix("0x") {
        compact = rest.to_string();
    } else if let Some(rest) = compact.strip_prefix("0X") {
        compact = rest.to_string();
    }

    let decoded = hex::decode(compact).ok()?;
    if decoded.len() != 32 {
        return None;
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Some(out)
}

fn load_ed25519_from_bytes(raw: &[u8]) -> Option<Ed25519SigningKey> {
    if raw.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(raw);
        return Some(Ed25519SigningKey::from_bytes(&key));
    }

    if let Ok(text) = std::str::from_utf8(raw) {
        if let Some(seed) = try_parse_hex_32(text) {
            return Some(Ed25519SigningKey::from_bytes(&seed));
        }
        if let Ok(signing_key) = Ed25519SigningKey::from_pkcs8_pem(text) {
            return Some(signing_key);
        }
    }

    if let Ok(signing_key) = Ed25519SigningKey::from_pkcs8_der(raw) {
        return Some(signing_key);
    }

    None
}

fn load_rsa_from_bytes(raw: &[u8]) -> Option<RsaPrivateKey> {
    if let Ok(text) = std::str::from_utf8(raw) {
        if let Ok(private_key) = RsaPrivateKey::from_pkcs8_pem(text) {
            return Some(private_key);
        }
        if let Ok(private_key) = RsaPrivateKey::from_pkcs1_pem(text) {
            return Some(private_key);
        }
    }

    if let Ok(private_key) = RsaPrivateKey::from_pkcs8_der(raw) {
        return Some(private_key);
    }
    if let Ok(private_key) = RsaPrivateKey::from_pkcs1_der(raw) {
        return Some(private_key);
    }

    None
}

struct OpenSshReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> OpenSshReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn tail(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn read_raw(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Some(out)
    }

    fn read_magic(&mut self, expected: &[u8]) -> bool {
        self.read_raw(expected.len()) == Some(expected)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let raw = self.read_raw(4)?;
        Some(u32::from_be_bytes(raw.try_into().ok()?))
    }

    fn read_string(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.read_raw(len)
    }

    fn read_mpint(&mut self) -> Option<BigUint> {
        let raw = self.read_string()?;
        if raw.is_empty() {
            return Some(BigUint::default());
        }
        if raw[0] & 0x80 != 0 {
            return None;
        }

        let mut value = raw;
        while value.len() > 1 && value[0] == 0 {
            value = &value[1..];
        }
        Some(BigUint::from_bytes_be(value))
    }
}

fn decode_openssh_private_key_pem(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    let begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    let end = "-----END OPENSSH PRIVATE KEY-----";

    if !text.contains(begin) {
        return None;
    }

    let mut in_block = false;
    let mut b64 = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == begin {
            in_block = true;
            continue;
        }
        if trimmed == end {
            break;
        }
        if in_block {
            b64.push_str(trimmed);
        }
    }

    if b64.is_empty() {
        return None;
    }

    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn check_padding_sequence(data: &[u8]) -> bool {
    for (idx, byte) in data.iter().enumerate() {
        if *byte != (idx as u8).wrapping_add(1) {
            return false;
        }
    }
    true
}

fn parse_openssh_signing_material(raw: &[u8]) -> io::Result<Option<SigningMaterial>> {
    let Some(decoded) = decode_openssh_private_key_pem(raw) else {
        return Ok(None);
    };

    let mut r = OpenSshReader::new(&decoded);
    if !r.read_magic(b"openssh-key-v1\0") {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid OpenSSH private key payload",
        ));
    }

    let ciphername = r
        .read_string()
        .and_then(|v| std::str::from_utf8(v).ok())
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH cipher name"))?;
    let kdfname = r
        .read_string()
        .and_then(|v| std::str::from_utf8(v).ok())
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH KDF name"))?;
    let _kdf_options = r
        .read_string()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH KDF options"))?;

    if ciphername != "none" || kdfname != "none" {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "encrypted OpenSSH private keys are not supported; decrypt or convert to PEM/DER first",
        ));
    }

    let key_count = r
        .read_u32()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH key count"))?;
    if key_count != 1 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "OpenSSH key files with multiple keys are not supported",
        ));
    }

    for _ in 0..key_count {
        r.read_string().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH public key section")
        })?;
    }

    let private_blob = r.read_string().ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "missing OpenSSH private key section",
        )
    })?;
    if r.remaining() != 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "unexpected trailing data in OpenSSH key payload",
        ));
    }

    let mut p = OpenSshReader::new(private_blob);
    let check1 = p
        .read_u32()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH checkint"))?;
    let check2 = p
        .read_u32()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH checkint"))?;
    if check1 != check2 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "OpenSSH checkints do not match; key data is corrupted",
        ));
    }

    let key_type = p
        .read_string()
        .and_then(|v| std::str::from_utf8(v).ok())
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH key type"))?;

    let material = match key_type {
        "ssh-ed25519" => {
            let public_key = p.read_string().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH Ed25519 public key")
            })?;
            let private_key = p.read_string().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid OpenSSH Ed25519 private key",
                )
            })?;
            p.read_string()
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH comment"))?;

            if public_key.len() != 32 || private_key.len() < 32 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid OpenSSH Ed25519 key lengths",
                ));
            }

            let mut seed = [0u8; 32];
            seed.copy_from_slice(&private_key[0..32]);
            let signing_key = Ed25519SigningKey::from_bytes(&seed);
            let derived_public = signing_key.verifying_key().to_bytes();
            if public_key != derived_public {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "OpenSSH Ed25519 public/private key mismatch",
                ));
            }

            SigningMaterial::Ed25519 {
                signing_key,
                public_key: derived_public,
            }
        }
        "ssh-rsa" => {
            let n = p.read_mpint().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH RSA modulus")
            })?;
            let e = p.read_mpint().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH RSA exponent")
            })?;
            let d = p.read_mpint().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid OpenSSH RSA private exponent",
                )
            })?;

            p.read_mpint().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid OpenSSH RSA CRT coefficient",
                )
            })?;
            let p_factor = p.read_mpint().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH RSA prime p")
            })?;
            let q_factor = p.read_mpint().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH RSA prime q")
            })?;
            p.read_string()
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid OpenSSH comment"))?;

            let rsa_key = RsaPrivateKey::from_components(n, e, d, vec![p_factor, q_factor])
                .map_err(|err| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("invalid OpenSSH RSA private key: {err}"),
                    )
                })?;
            rsa_key.validate().map_err(|err| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("OpenSSH RSA key failed validation: {err}"),
                )
            })?;

            let public_key = RsaPublicKey::from(&rsa_key);
            let public_key_der = public_key.to_public_key_der().map_err(|err| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to encode RSA public key DER: {err}"),
                )
            })?;

            SigningMaterial::Rsa {
                signing_key: rsa_key,
                public_key_der: public_key_der.as_ref().to_vec(),
            }
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unsupported OpenSSH key type '{key_type}'"),
            ));
        }
    };

    if !check_padding_sequence(p.tail()) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid OpenSSH private key padding",
        ));
    }

    Ok(Some(material))
}

pub fn load_signing_material(private_key_path: &Path) -> io::Result<SigningMaterial> {
    let raw = read_all_bytes(private_key_path)?;

    if let Some(openssh_key) = parse_openssh_signing_material(&raw)? {
        return Ok(openssh_key);
    }

    if let Some(ed25519_key) = load_ed25519_from_bytes(&raw) {
        return Ok(SigningMaterial::Ed25519 {
            public_key: ed25519_key.verifying_key().to_bytes(),
            signing_key: ed25519_key,
        });
    }

    if let Some(rsa_key) = load_rsa_from_bytes(&raw) {
        let public_key = RsaPublicKey::from(&rsa_key);
        let public_key_der = public_key.to_public_key_der().map_err(|err| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("failed to encode RSA public key DER: {err}"),
            )
        })?;

        return Ok(SigningMaterial::Rsa {
            signing_key: rsa_key,
            public_key_der: public_key_der.as_ref().to_vec(),
        });
    }

    Err(io::Error::new(
        ErrorKind::InvalidData,
        "unsupported private key format; expected OpenSSH (ed25519/rsa, unencrypted), Ed25519 (raw 32-byte seed, hex, PKCS#8 PEM/DER), or RSA (PKCS#1/PKCS#8 PEM/DER)",
    ))
}
