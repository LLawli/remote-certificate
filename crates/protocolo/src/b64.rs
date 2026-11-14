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

/// Uma lista de bytes, cada um em base64 (`#[serde(with = "crate::b64::lista")]`).
pub mod lista {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(itens: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(itens.len()))?;
        for bytes in itens {
            seq.serialize_element(&STANDARD.encode(bytes))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|texto| STANDARD.decode(texto).map_err(serde::de::Error::custom))
            .collect()
    }
}
