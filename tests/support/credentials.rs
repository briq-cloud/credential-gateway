//! Runtime-only synthetic credential material, independent of user configuration or env.

use rand::TryRngCore;

/// Exact byte lengths keep framing, expansion and admission fixtures reproducible.
pub fn ascii(bytes: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut entropy = vec![0; bytes.div_ceil(2)];
    rand::rngs::OsRng
        .try_fill_bytes(&mut entropy)
        .expect("fixture entropy unavailable");
    entropy
        .into_iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .take(bytes)
        .map(char::from)
        .collect()
}

/// Random password with a colon/UTF-8 and alphabet-normalization exercise. Its length is
/// divisible by three, retaining all three alignment classes for the public usernames.
pub fn structured() -> String {
    format!("{}:é~??/", ascii(32))
}
