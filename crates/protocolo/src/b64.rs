//! Bytes como base64 padrão no JSON (`#[serde(with = "crate::b64")]`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&STANDARD.encode(bytes))
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let texto = String::deserialize(d)?;
    STANDARD.decode(texto).map_err(serde::de::Error::custom)
}
