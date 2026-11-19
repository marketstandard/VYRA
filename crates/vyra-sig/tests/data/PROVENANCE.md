# Test vector provenance

All files here are test data only. They are parsed by the integration tests
and never executed.

## ML-DSA-sigGen-FIPS204-external-pure.json.gz / ML-DSA-sigVer-FIPS204-external-pure.json.gz

- Source: NIST ACVP-Server, <https://github.com/usnistgov/ACVP-Server>
- Repository commit: `975de31eb83d87039ec88934fdc47d8c312b892d` (committed 2026-08-12)
- Original files (downloaded 2026-11-18):
  - `gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json`,
    8,971,659 bytes, SHA-256 `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22`
  - `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`,
    4,533,178 bytes, SHA-256 `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437`
- Subset rule (deterministic): keep the top-level object, and from `testGroups` keep
  exactly the groups with `signatureInterface == "external"`,
  `preHash == "pure"` and `externalMu == false`. Test cases inside a kept group are
  unchanged and complete. The result is serialized with
  `json.dumps(obj, sort_keys=True, separators=(",", ":"))` and gzip-compressed
  with `mtime=0` and no file name.
  - sigGen: groups tgId 1, 3, 5 (deterministic) and 13, 15, 17 (hedged, given
    `rnd`); 15 cases each = 90 cases (30 per parameter set). Contexts 0..255
    bytes, messages 1..8192 bytes.
  - sigVer: groups tgId 1, 3, 5; 15 cases each = 45 cases (per parameter set
    3 valid, 12 invalid: modified message, commitment, z, hint).
- Excluded groups and why:
  - `preHash == "preHash"` (HashML-DSA): VYRA uses pure ML-DSA only.
  - `signatureInterface == "internal"` (ML-DSA.Sign_internal / Verify_internal,
    with or without external μ): VYRA uses only the external FIPS 204
    Algorithm 2/3 interface with a context string.
- Subset files (as committed):
  - `ML-DSA-sigGen-FIPS204-external-pure.json.gz`: uncompressed JSON SHA-256
    `593da8e9ea4a8fe80ad885272a9d8837b18866abe680fd3928cf298ad79fbe9d`;
    gzip SHA-256 `c342dc491c0e8b21a8c9cf27aca55c68b608d16465806618f8fbe8c03ac509ef`
  - `ML-DSA-sigVer-FIPS204-external-pure.json.gz`: uncompressed JSON SHA-256
    `beeaf030489ca2af7095d968ea451e35331b46734cabbfd3f6cb2dd63dde5559`;
    gzip SHA-256 `31d7eaa8459f1cb2f58bd209b99eef1b3b78a2c40405c575411ede2179e3bd76`

## SLH-DSA-keyGen-FIPS205-shake-s.json.gz / SLH-DSA-sigGen-FIPS205-shake-s-external-pure.json.gz / SLH-DSA-sigVer-FIPS205-shake-s-external-pure.json.gz

- Source: NIST ACVP-Server, <https://github.com/usnistgov/ACVP-Server>
- Repository commit: `975de31eb83d87039ec88934fdc47d8c312b892d` (tag `v1.1.0.43`,
  committed 2026-08-12; the same commit as the ML-DSA files above)
- Original files (downloaded 2026-11-18 from `raw.githubusercontent.com` at that
  commit, i.e. the git blobs without any line-ending conversion; RULES 19). Git
  blob ids recomputed locally with `git hash-object` and equal to the ids in the
  GitHub tree at that commit:
  - `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json`,
    75,294 bytes, SHA-256 `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920`,
    git blob `bd99c97086a6f4fc4f5dfb88df70de62befb7dae`
  - `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json`,
    38,178,342 bytes, SHA-256 `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba`,
    git blob `5ff182bc29ae00b02a219cf68fff370d9963a12c`
  - `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`,
    30,731,848 bytes, SHA-256 `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792`,
    git blob `0805107118f6d2c171f15b005e0b2bb0ec1ddcc1`
- Subset rule (deterministic): keep the top-level object, and from `testGroups` keep
  exactly the groups with `parameterSet` in {`SLH-DSA-SHAKE-128s`,
  `SLH-DSA-SHAKE-192s`, `SLH-DSA-SHAKE-256s`} and, for sigGen and sigVer,
  additionally `signatureInterface == "external"` and `preHash == "pure"`. Test
  cases inside a kept group are unchanged and complete. Serialized with
  `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, gzip-compressed with
  `mtime=0`, no file name, level 9.
  - keyGen: groups tgId 2, 6, 10; 10 cases each = 30 cases (`skSeed`, `skPrf`,
    `pkSeed` → `pk`, `sk`).
  - sigGen: groups tgId 25, 27, 29 (deterministic) and 61, 63, 65 (hedged, given
    `additionalRandomness`); 7 cases each = 42 cases (14 per parameter set).
    Contexts 0..255 bytes (each group includes the empty context), messages
    1..8192 bytes. The secret key is the standard 4n-byte FIPS 205 encoding.
  - sigVer: groups tgId 25, 27, 29; 14 cases each = 42 cases (per parameter set
    2 valid; 12 invalid: modified message, modified R, modified SIG_FORS,
    modified SIG_HT, signature too large, signature too small, 2 each).
- Excluded groups and why: the SHA2 parameter sets and the SHAKE "f" sets (VYRA
  uses SHAKE "s" only); `preHash == "preHash"` (HashSLH-DSA: VYRA uses pure
  SLH-DSA only); `signatureInterface == "internal"` (`slh_sign_internal` /
  `slh_verify_internal` without the `0x00 ‖ len(ctx) ‖ ctx` prefix: VYRA uses only
  the external FIPS 205 Algorithm 22/24 interface with a context string).
- Subset files (as committed):
  - `SLH-DSA-keyGen-FIPS205-shake-s.json.gz`: uncompressed JSON 15,685 bytes, SHA-256
    `e6a9dae3db15edb2ce194edf5ccf14e0831f2643461bc32264180264cf90b3e0`;
    gzip SHA-256 `dff768efec7a2b77631989a9ae1d53b96a341e1dc48c7c968ae36460e9a1f321`
  - `SLH-DSA-sigGen-FIPS205-shake-s-external-pure.json.gz`: uncompressed JSON
    1,950,178 bytes, SHA-256
    `e6d041603fac35cc96a088878fe2a1764d5a668f14417fcf33efc3511f9e87ea`;
    gzip SHA-256 `90b5e331115e50f50f02402041dde78e54b5f5ab48a667ccdc6ee369afa4e23c`
  - `SLH-DSA-sigVer-FIPS205-shake-s-external-pure.json.gz`: uncompressed JSON
    1,845,659 bytes, SHA-256
    `c05eb8dbbbded756881b9dc5a797c8420429969fd49136c2d0be169beacde13f`;
    gzip SHA-256 `32691893eba94912a6729d6ba7e68283fca4c89afccdb29fb07eeb3c9e7b41d5`

## ML-DSA-keyGen-FIPS204-internalProjection.json.gz

- Source: NIST ACVP-Server `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json`,
  copied byte-for-byte (already gzip-compressed) from the `fips204` 0.5.0 crate package
  (`tests/nist_vectors/ML-DSA-keyGen-FIPS204/internalProjection.json.gz`).
- gzip SHA-256 `1717b3497b96c16e6b9556be467c5bbc6dd113d962aa0a02bd669eadaef8c01b`
- 75 cases, 25 per parameter set (seed → pk, sk).
