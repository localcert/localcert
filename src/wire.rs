pub mod client;
pub mod domain;
pub mod provision;

mod b64wrap {
    use serde::{ser, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &impl Serialize,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = serde_json::to_vec(value).map_err(ser::Error::custom)?;
        serializer.serialize_str(base64::encode(bytes).as_str())
    }
}
