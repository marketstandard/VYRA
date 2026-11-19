# VYRA benchmarks

**Read this first.** These are wall-clock timings on one machine, taken with `std::time::Instant` around single operations. They are not cycle-accurate, are affected by frequency scaling and background load, and are **not a constant-time evaluation**: nothing here says anything about timing side channels.

- CPU: 13th Gen Intel(R) Core(TM) i9-13900K
- OS: windows x86_64
- rustc: rustc 1.98.0 (88d9e12ae 2026-08-18)
- date (UTC): 2026-11-19T07:53:26Z
- crate versions: {"chacha20poly1305":["0.11.0"],"ed25519-dalek":["3.0.0"],"fips205":["0.5.0"],"ml-dsa":["0.1.2"],"ml-kem":["0.3.4"],"sha3":["0.10.9","0.11.0","0.12.0"],"vyra-hqc":["0.1.0"]}
- profile: {"debug_assertions":false,"name":"release","overrides":"none (workspace Cargo.toml has no [profile.release]; cargo defaults: opt-level=3, lto=false, codegen-units=16, debug=false)"}
- iterations: {"default_ops":200,"one_mib_ops":50,"quick":false,"slh_dsa_keygen_ops":20,"slh_dsa_sign_ops":10,"slh_dsa_verify_ops":200,"warmup":"max(3, iterations / 10) untimed runs before timing; 1 run before SLH-DSA-based keygen and sign (dual post-quantum suites and sig-component rows); each row records its own warmup"}

All times in microseconds (us).

## kem-suite

| name | op | n | median | mean | min | p95 | stddev |
|---|---|---|---|---|---|---|---|
| VYRA-KEM-1 | keygen | 200 | 176.5 | 179.5 | 174.1 | 189.2 | 12.8 |
| VYRA-KEM-1 | encaps | 200 | 359.4 | 363.9 | 352.2 | 386.2 | 20.7 |
| VYRA-KEM-1 | decaps | 200 | 719.0 | 725.1 | 700.6 | 749.0 | 31.9 |
| VYRA-KEM-3 | keygen | 200 | 503.9 | 533.8 | 491.8 | 753.5 | 111.7 |
| VYRA-KEM-3 | encaps | 200 | 1021.3 | 1028.8 | 991.9 | 1070.9 | 51.6 |
| VYRA-KEM-3 | decaps | 200 | 1999.2 | 2267.0 | 1941.6 | 3861.6 | 586.9 |
| VYRA-KEM-5 | keygen | 200 | 1383.7 | 1302.8 | 898.6 | 1780.9 | 335.9 |
| VYRA-KEM-5 | encaps | 200 | 1816.3 | 1820.7 | 1759.5 | 1888.8 | 39.1 |
| VYRA-KEM-5 | decaps | 200 | 3573.6 | 3671.4 | 3516.1 | 3679.5 | 495.1 |

## kem-component

| name | op | n | median | mean | min | p95 | stddev |
|---|---|---|---|---|---|---|---|
| ML-KEM-512 | keygen | 200 | 46.4 | 47.2 | 45.9 | 48.1 | 6.2 |
| ML-KEM-512 | encaps | 200 | 57.8 | 58.1 | 57.5 | 59.2 | 1.3 |
| ML-KEM-512 | decaps | 200 | 116.9 | 117.6 | 116.6 | 123.3 | 2.1 |
| ML-KEM-768 | keygen | 200 | 78.2 | 78.9 | 77.5 | 83.8 | 3.2 |
| ML-KEM-768 | encaps | 200 | 91.6 | 92.3 | 90.8 | 96.5 | 2.6 |
| ML-KEM-768 | decaps | 200 | 161.8 | 161.9 | 121.7 | 183.4 | 25.4 |
| ML-KEM-1024 | keygen | 200 | 82.3 | 83.0 | 79.9 | 88.4 | 2.6 |
| ML-KEM-1024 | encaps | 200 | 88.8 | 89.8 | 85.4 | 96.2 | 3.3 |
| ML-KEM-1024 | decaps | 200 | 178.2 | 179.0 | 175.4 | 183.7 | 3.5 |
| HQC-128 | keygen | 200 | 147.4 | 148.2 | 142.7 | 155.8 | 4.6 |
| HQC-128 | encaps | 200 | 292.1 | 293.9 | 286.1 | 305.4 | 8.3 |
| HQC-128 | decaps | 200 | 603.4 | 614.8 | 592.5 | 638.8 | 58.7 |
| HQC-192 | keygen | 200 | 433.2 | 438.6 | 429.6 | 447.5 | 38.1 |
| HQC-192 | encaps | 200 | 876.6 | 892.2 | 861.9 | 932.4 | 75.4 |
| HQC-192 | decaps | 200 | 1792.0 | 1842.7 | 1761.8 | 2383.0 | 159.8 |
| HQC-256 | keygen | 200 | 794.6 | 825.6 | 788.5 | 852.6 | 138.6 |
| HQC-256 | encaps | 200 | 1602.5 | 1614.9 | 1588.6 | 1661.2 | 45.5 |
| HQC-256 | decaps | 200 | 4307.9 | 4798.3 | 3241.3 | 6585.6 | 1477.0 |

## sig-suite

| name | op | n | median | mean | min | p95 | stddev |
|---|---|---|---|---|---|---|---|
| VYRA-SIG-2 | keygen | 200 | 246.2 | 260.8 | 203.5 | 383.8 | 70.3 |
| VYRA-SIG-2 | sign-1KiB | 200 | 1014.7 | 1163.0 | 462.5 | 2492.8 | 583.9 |
| VYRA-SIG-2 | verify-1KiB | 200 | 192.4 | 193.9 | 188.0 | 200.8 | 8.3 |
| VYRA-SIG-3 | keygen | 200 | 235.3 | 241.3 | 221.6 | 261.4 | 13.1 |
| VYRA-SIG-3 | sign-1KiB | 200 | 1093.8 | 1277.9 | 641.7 | 2529.1 | 656.9 |
| VYRA-SIG-3 | verify-1KiB | 200 | 254.1 | 255.7 | 251.7 | 264.5 | 5.8 |
| VYRA-SIG-5 | keygen | 200 | 342.4 | 348.9 | 324.0 | 392.0 | 28.2 |
| VYRA-SIG-5 | sign-1KiB | 200 | 1469.0 | 1731.7 | 972.2 | 3524.8 | 840.2 |
| VYRA-SIG-5 | verify-1KiB | 200 | 500.8 | 477.0 | 350.0 | 531.1 | 59.8 |
| VYRA-SIG-PQ1 | keygen | 20 | 138097.5 | 150329.3 | 135665.3 | 184244.3 | 25079.9 |
| VYRA-SIG-PQ1 | sign-1KiB | 10 | 1326916.4 | 1383168.6 | 1278837.8 | 1626648.2 | 128188.8 |
| VYRA-SIG-PQ1 | verify-1KiB | 200 | 1175.2 | 1450.6 | 1033.0 | 2193.6 | 425.1 |
| VYRA-SIG-PQ3 | keygen | 20 | 195847.1 | 204853.5 | 192097.7 | 250367.6 | 20259.9 |
| VYRA-SIG-PQ3 | sign-1KiB | 10 | 2371221.0 | 2381072.1 | 2191395.3 | 2641058.8 | 147134.4 |
| VYRA-SIG-PQ3 | verify-1KiB | 200 | 1565.5 | 1756.6 | 1477.7 | 2647.6 | 369.7 |
| VYRA-SIG-PQ5 | keygen | 20 | 134631.6 | 139614.9 | 129272.9 | 167678.3 | 13659.0 |
| VYRA-SIG-PQ5 | sign-1KiB | 10 | 1825988.9 | 1853336.4 | 1737589.1 | 2098116.5 | 105858.4 |
| VYRA-SIG-PQ5 | verify-1KiB | 200 | 2409.9 | 2417.6 | 2320.9 | 2480.4 | 95.4 |

## sig-component

| name | op | n | median | mean | min | p95 | stddev |
|---|---|---|---|---|---|---|---|
| SLH-DSA-SHAKE-128s | keygen | 20 | 135929.3 | 134878.6 | 126431.3 | 140647.7 | 4942.3 |
| SLH-DSA-SHAKE-128s | sign-1KiB | 10 | 1160996.4 | 1201704.6 | 1103062.6 | 1470075.6 | 112502.8 |
| SLH-DSA-SHAKE-128s | verify-1KiB | 200 | 937.6 | 946.1 | 922.2 | 968.9 | 67.8 |
| SLH-DSA-SHAKE-192s | keygen | 20 | 196712.6 | 197740.9 | 193390.6 | 204493.0 | 3530.9 |
| SLH-DSA-SHAKE-192s | sign-1KiB | 10 | 2175890.4 | 2181529.7 | 1993131.1 | 2406021.6 | 130241.6 |
| SLH-DSA-SHAKE-192s | verify-1KiB | 200 | 1572.7 | 1945.5 | 1512.4 | 3242.6 | 557.5 |
| SLH-DSA-SHAKE-256s | keygen | 20 | 133132.3 | 148401.1 | 126353.2 | 191823.9 | 25669.8 |
| SLH-DSA-SHAKE-256s | sign-1KiB | 10 | 1703096.9 | 1715859.8 | 1655569.2 | 1813625.6 | 53365.6 |
| SLH-DSA-SHAKE-256s | verify-1KiB | 200 | 2087.2 | 2335.9 | 2042.9 | 4004.3 | 598.9 |

## seal

| name | op | n | median | mean | min | p95 | stddev |
|---|---|---|---|---|---|---|---|
| VYRA-KEM-1 | seal-1KiB | 200 | 390.6 | 416.4 | 378.0 | 742.6 | 93.3 |
| VYRA-KEM-1 | open-1KiB | 200 | 752.9 | 756.2 | 718.8 | 802.7 | 26.8 |
| VYRA-KEM-1 | seal-1MiB | 50 | 1193.7 | 1238.5 | 1171.6 | 1704.1 | 144.3 |
| VYRA-KEM-1 | open-1MiB | 50 | 1650.2 | 1660.6 | 1622.5 | 1724.4 | 34.7 |
| VYRA-KEM-3 | seal-1KiB | 200 | 1050.8 | 1054.1 | 1013.6 | 1097.1 | 22.1 |
| VYRA-KEM-3 | open-1KiB | 200 | 2025.7 | 2042.2 | 1965.5 | 2105.4 | 125.8 |
| VYRA-KEM-3 | seal-1MiB | 50 | 1811.8 | 1820.2 | 1793.7 | 1883.1 | 22.7 |
| VYRA-KEM-3 | open-1MiB | 50 | 2960.9 | 3059.4 | 2890.7 | 3105.0 | 470.2 |
| VYRA-KEM-5 | seal-1KiB | 200 | 1845.7 | 1850.2 | 1810.7 | 1897.6 | 26.4 |
| VYRA-KEM-5 | open-1KiB | 200 | 3606.3 | 3615.3 | 3473.1 | 3754.9 | 107.0 |
| VYRA-KEM-5 | seal-1MiB | 50 | 2695.4 | 2688.6 | 2554.4 | 2771.3 | 60.1 |
| VYRA-KEM-5 | open-1MiB | 50 | 4608.8 | 4672.0 | 4352.0 | 5800.9 | 405.6 |
