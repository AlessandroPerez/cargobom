//! Validation against the vendored CycloneDX 1.7 schemas (offline; the registry enums for
//! algorithm families and curves come with `cryptography-defs.schema.json`).

use anyhow::{Result, anyhow};
use serde_json::Value;

const SCHEMAS: &[(&str, &str)] = &[
    (
        "bom-1.7.schema.json",
        include_str!("../../../schema/bom-1.7.schema.json"),
    ),
    (
        "spdx.schema.json",
        include_str!("../../../schema/spdx.schema.json"),
    ),
    (
        "jsf-0.82.schema.json",
        include_str!("../../../schema/jsf-0.82.schema.json"),
    ),
    (
        "cryptography-defs.schema.json",
        include_str!("../../../schema/cryptography-defs.schema.json"),
    ),
];

struct Vendored;

impl jsonschema::Retrieve for Vendored {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let s = uri.as_str();
        let file = s.rsplit('/').next().unwrap_or(s);
        SCHEMAS
            .iter()
            .find(|(n, _)| *n == file)
            .map(|(_, text)| serde_json::from_str(text).unwrap())
            .ok_or_else(|| format!("schema {s} is not vendored").into())
    }
}

/// Schema errors, as `path: message`; empty when the document is valid.
pub fn validate(doc: &Value) -> Result<Vec<String>> {
    let schema: Value = serde_json::from_str(SCHEMAS[0].1)?;
    let v = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .with_retriever(Vendored)
        .build(&schema)
        .map_err(|e| anyhow!("loading the CycloneDX schema: {e}"))?;
    Ok(v.iter_errors(doc)
        .map(|e| format!("{}: {}", e.instance_path(), e))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn asset(family: &str) -> Value {
        json!({
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [{
                "type": "cryptographic-asset", "name": "AES-256-GCM", "bom-ref": "a",
                "cryptoProperties": { "assetType": "algorithm",
                    "algorithmProperties": { "primitive": "ae", "algorithmFamily": family } }
            }]
        })
    }

    #[test]
    fn registry_families_are_enforced() {
        assert!(validate(&asset("AES")).unwrap().is_empty());
        assert!(!validate(&asset("NOT-A-FAMILY")).unwrap().is_empty());
    }
}
