# Provenance of the HQC v5.1 test data

Fetched 2026-11-18 from the official HQC repository
<https://gitlab.com/pqc-hqc/hqc>, tag **`v5.1.0`** (annotated tag object
`bd3ed177e883aa04ba2db6b029599d662f88ca6f`, commit
**`06567ccbad10580d78dd7863b15d23f41076d57f`**, "Release v5.1.0", 2026-10-26).
The same tag matches the specification **HQC version 5.1 (2026/11/09)**,
<https://pqc-hqc.org/doc/hqc_specifications_v5.1.pdf> (fetched the same day;
HTTP Last-Modified 2026-11-09, SHA-256
`45be0bc16b6a44836a5f6d9f7bafbaf39e368d0bceac6aa1fea64d1320471b2f`).

The files were read as data only; nothing from the repository was built or run.

## Source files

Hashes are of the files as stored in git (LF line endings). A Windows checkout
with `core.autocrlf=true` converts them to CRLF and changes the SHA-256.

| Path at v5.1.0 | git blob | SHA-256 |
|---|---|---|
| `kats/ref/hqc-1/PQCkemKAT_32.rsp` | `fb9c08596c2e3cee26f35d12fdc8d5964d082fe4` | `c3f6ce304a00685e3aa356ef7cd81dbb35d985a1ff7123610bed9582e3638c1e` |
| `kats/ref/hqc-3/PQCkemKAT_32.rsp` | `602f71712a52cfc1ecf8e112443db69edbd02399` | `7dcb2b670d1e108c0d7dc0c88b466c63c121de5ac4f96fd2e868c7040065a4ff` |
| `kats/ref/hqc-5/PQCkemKAT_32.rsp` | `611268a8480e9dc0a77194cc6f4b4654fdedf141` | `e5066df4ec3dbe012d60a4a66ce5e0c2f1996d11af8a8eb66333f15b51095edb` |
| `kats/rs/hqc-1/rs.tv` | `e478fc73454fe87d0ddaaf6e3e94bdace9ca2f32` | `745b727bbbd679649346d41e799bd8d07afd9fab1e955c5a4c8371786b41c2a3` |
| `kats/rs/hqc-3/rs.tv` | `7779b4d0bb78a633e84c40d6f5881c8737a1278a` | `57b316d844a53d47dcdc9ee6e120cbe30d815bec4ac0aa753d8c10d0dcc81f76` |
| `kats/rs/hqc-5/rs.tv` | `c157d299f054245c6fca531083883789dbc95f67` | `c84b656037b87e1d880ddbee6297a06bb23ebcf4a715da738835947c0be07785` |

The `kats/x86_64/avx256/hqc-*/PQCkemKAT_32.rsp` files are byte-identical to the
`kats/ref` ones (same blob ids).

The KAT files were produced by `packaging/utils/helpers/main_kat.c` with the
NIST AES-256 CTR DRBG of `lib/nist-rng/rng.c` (`tools/kat_generator.sh`): the
DRBG is seeded with the bytes 0..47 and draws 100 48-byte seeds; for each count
it is re-seeded with that seed and `hqc_kem_keygen` (one `randombytes(32)`)
and `hqc_kem_encaps` (`randombytes(k)`, then `randombytes(16)`) run; the
generator then checks that `hqc_kem_decaps` returns the same `ss`.

## Embedded files (derived)

The full KAT files are 1.4 to 4.4 MB each, so a complete subset is embedded:

- `hqc-{1,3,5}/kat-digests.txt`: for **every** count 0..99, one line
  `count seed sk SHA3-256(pk) SHA3-256(ct) ss` (hex). `seed`, `sk` (32 bytes in
  v5.1) and `ss` are the exact KAT values; `pk` and `ct` are pinned by
  SHA3-256 of their bytes.
- `hqc-{1,3,5}/PQCkemKAT_32.counts0-4.rsp`: the exact byte prefix of the
  official `.rsp` file up to (excluding) the line `count = 5`, i.e. the header
  and counts 0..4 in full. SHA-256 (checked by `tests/kat.rs`):
  - hqc-1: 68084 bytes, `f6cf24bdb6dac8d134482bb27450c671bd09733b9b8b5a264ef2c0c16eec868e`
  - hqc-3: 136264 bytes, `f5715d70288e767c990b09ac9549bf9e6eb77cdf68d399ad43f8376da184752a`
  - hqc-5: 217924 bytes, `da8a22b1ef96328b0cefe8116e74bac2c04f519a65931c91f8090f703ff70ef1`
- `rs/hqc-{1,3,5}-rs-subset.txt`: the first 25 samples of each of the 8
  scenarios of `kats/rs/hqc-*/rs.tv` (200 per set), fields
  `scenario message codeword corrupted decoded` with spaces removed from the
  hex. Used by the unit tests in `src/reed_solomon.rs`.

The derived files were written by a short script (Python `hashlib.sha3_256`)
that parsed the official files; `tests/kat.rs` cross-checks that both embedded
forms agree on counts 0..4 and that the DRBG reproduces all 100 seeds.

`crates/vyra-kem/tests/conformance_hqc.rs` reuses `kat-digests.txt`.
