CycloneDX 1.7 JSON schemas, vendored so CBOM validation runs offline (Apache-2.0,
https://github.com/CycloneDX/specification/tree/master/schema, fetched 2026-10-07).
`cryptography-defs.schema.json` carries the Cryptography Registry enums (algorithm families,
elliptic curves) that `bom-1.7.schema.json` references.

`cryptography-defs.json` is the Cryptography Registry itself (`lastUpdated` 2026-02-24, same
source and licence): for each family, the variant name patterns (`AES[-(128|192|256)][-(GCM|CCM)]
[-{tagLength}][-{ivLength}]`). The schema only enforces families; `rcbom-kb`'s `registry` module
checks every asset name against these patterns.
