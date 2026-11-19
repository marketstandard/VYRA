//! End-to-end tests of the `vyra` binary: the demo, file-based flows for
//! every suite (one full flow per dual post-quantum signature suite, each in
//! its own test because SLH-DSA signing takes seconds), and error handling
//! (non-zero exit, message on stderr, never a panic).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use vyra::kem::KemSuite;
use vyra::seal::SealedBox;
use vyra::sig::SigSuite;

/// A unique scratch directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "vyra-cli-test-{name}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Run the binary with `args`.
fn vyra(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vyra"))
        .args(args)
        .output()
        .expect("run vyra binary")
}

fn s(text: &str) -> &OsStr {
    OsStr::new(text)
}

fn p(path: &Path) -> &OsStr {
    path.as_os_str()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_no_panic(out: &Output) {
    assert!(
        !stderr(out).contains("panicked"),
        "binary panicked: {}",
        stderr(out)
    );
}

/// Assert success (exit 0) without a panic.
fn assert_ok(out: &Output, what: &str) {
    assert_no_panic(out);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{what}: expected exit 0\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out)
    );
}

/// Assert exit code `code` (non-zero), a message on stderr, and no panic.
fn assert_fails(out: &Output, code: i32, what: &str) {
    assert_no_panic(out);
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what}: expected exit {code}\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out)
    );
    assert!(
        stderr(out).contains("vyra: error:"),
        "{what}: no error message on stderr: {}",
        stderr(out)
    );
}

fn kem_keygen(dir: &TempDir, suite: KemSuite, tag: &str) -> (PathBuf, PathBuf) {
    let pk = dir.path(&format!("{tag}.kem.pk"));
    let sk = dir.path(&format!("{tag}.kem.sk"));
    let id = suite.id().to_string();
    let out = vyra(&[
        s("kem"),
        s("keygen"),
        s("--suite"),
        s(&id),
        s("--pk"),
        p(&pk),
        s("--sk"),
        p(&sk),
    ]);
    assert_ok(&out, "kem keygen");
    (pk, sk)
}

/// The `--suite` value for a signature suite. The dual post-quantum suites
/// are spelled in different cases on purpose (parsing is case-insensitive).
fn sig_suite_arg(suite: SigSuite) -> &'static str {
    match suite {
        SigSuite::Vyra2 => "2",
        SigSuite::Vyra3 => "3",
        SigSuite::Vyra5 => "5",
        SigSuite::Pq1 => "PQ1",
        SigSuite::Pq3 => "pq3",
        SigSuite::Pq5 => "Pq5",
    }
}

fn sig_keygen(dir: &TempDir, suite: SigSuite, tag: &str) -> (PathBuf, PathBuf) {
    let pk = dir.path(&format!("{tag}.sig.pk"));
    let sk = dir.path(&format!("{tag}.sig.sk"));
    let out = vyra(&[
        s("sig"),
        s("keygen"),
        s("--suite"),
        s(sig_suite_arg(suite)),
        s("--pk"),
        p(&pk),
        s("--sk"),
        p(&sk),
    ]);
    assert_ok(&out, "sig keygen");
    assert!(stdout(&out).contains(suite.name()), "{}", stdout(&out));
    (pk, sk)
}

#[test]
fn demo_exits_zero_and_prints_pass() {
    let out = vyra(&[s("demo")]);
    assert_ok(&out, "demo");
    let text = stdout(&out);
    assert!(text.contains("RESEARCH PROTOTYPE"), "{text}");
    assert!(text.contains("PASS: all"), "{text}");
    assert!(!text.contains("FAIL"), "{text}");
    for suite in SigSuite::all() {
        assert!(text.contains(&format!("[SIG] {}:", suite.name())), "{text}");
    }
    assert!(text.contains("ML-DSA-87 + SLH-DSA-SHAKE-256s (dual post-quantum)"));
    assert_eq!(
        text.matches("6 of 6 signature checks run").count(),
        SigSuite::all().len(),
        "{text}"
    );
}

#[test]
fn info_and_help() {
    let out = vyra(&[s("info")]);
    assert_ok(&out, "info");
    let text = stdout(&out);
    for needle in [
        "RESEARCH PROTOTYPE",
        "VYRA-KEM-1",
        "VYRA-KEM-5",
        "VYRA-SIG-2",
        "ML-KEM-768 + HQC-192",
        "ML-DSA-87 + Ed25519",
        "VYRA-SIG-PQ1",
        "VYRA-SIG-PQ5",
        "ML-DSA-44 + SLH-DSA-SHAKE-128s",
        "ML-DSA-65 + SLH-DSA-SHAKE-192s",
        "Dual post-quantum suites",
        "Transition suites",
        "signature take",
        &SealedBox::overhead(KemSuite::Vyra3).to_string(),
        &KemSuite::Vyra5.encoded_ciphertext_len().to_string(),
        &SigSuite::Vyra5.encoded_signature_len().to_string(),
        &SigSuite::Pq5.encoded_signature_len().to_string(),
        &SigSuite::Pq3.encoded_secret_key_len().to_string(),
    ] {
        assert!(text.contains(needle), "info lacks {needle:?}:\n{text}");
    }
    // Component names come from the suite: no dual-PQ row names Ed25519.
    for suite in SigSuite::dual_pq() {
        let row = text
            .lines()
            .find(|l| l.trim_start().starts_with(suite.name()))
            .unwrap_or_else(|| panic!("no row for {}", suite.name()));
        assert!(!row.contains("Ed25519"), "{row}");
        assert!(row.contains(suite.second().name()), "{row}");
    }

    for args in [
        &[s("help")][..],
        &[s("--help")][..],
        &[s("kem"), s("-h")][..],
    ] {
        let out = vyra(args);
        assert_ok(&out, "help");
        assert!(stdout(&out).contains("USAGE:"));
        assert!(stdout(&out).contains("your responsibility"));
    }
}

#[test]
fn kem_flow_every_suite() {
    let dir = TempDir::new("kem");
    for suite in KemSuite::all() {
        let tag = suite.id().to_string();
        let (pk, sk) = kem_keygen(&dir, suite, &tag);
        assert_eq!(fs::read(&pk).unwrap().len(), suite.encoded_public_key_len());
        assert_eq!(fs::read(&sk).unwrap().len(), suite.encoded_secret_key_len());

        let ct = dir.path(&format!("{tag}.ct"));
        let ss_enc = dir.path(&format!("{tag}.ss.enc"));
        let ss_dec = dir.path(&format!("{tag}.ss.dec"));
        let out = vyra(&[
            s("kem"),
            s("encaps"),
            s("--pk"),
            p(&pk),
            s("--ct"),
            p(&ct),
            s("--ss"),
            p(&ss_enc),
        ]);
        assert_ok(&out, "kem encaps");
        let out = vyra(&[
            s("kem"),
            s("decaps"),
            s("--sk"),
            p(&sk),
            s("--ct"),
            p(&ct),
            s("--ss"),
            p(&ss_dec),
        ]);
        assert_ok(&out, "kem decaps");

        let a = fs::read(&ss_enc).unwrap();
        let b = fs::read(&ss_dec).unwrap();
        assert_eq!(a.len(), suite.shared_secret_len());
        assert_eq!(a, b, "{suite}: shared secrets differ");
        assert_eq!(fs::read(&ct).unwrap().len(), suite.encoded_ciphertext_len());
        // The shared secret is never printed (hex or otherwise).
        let hex: String = a.iter().map(|x| format!("{x:02x}")).collect();
        assert!(!stdout(&out).contains(&hex) && !stderr(&out).contains(&hex));

        // Another key of the same suite: implicit rejection, a different secret.
        let (_, other_sk) = kem_keygen(&dir, suite, &format!("{tag}-other"));
        let ss_other = dir.path(&format!("{tag}.ss.other"));
        let out = vyra(&[
            s("kem"),
            s("decaps"),
            s("--sk"),
            p(&other_sk),
            s("--ct"),
            p(&ct),
            s("--ss"),
            p(&ss_other),
        ]);
        assert_ok(&out, "kem decaps with another key");
        assert_ne!(fs::read(&ss_other).unwrap(), a);
    }
}

#[test]
fn sig_flow_transition_suites() {
    let dir = TempDir::new("sig");
    let msg = dir.path("message.txt");
    let modified = dir.path("modified.txt");
    fs::write(&msg, b"release notes v1\n").unwrap();
    fs::write(&modified, b"release notes v2\n").unwrap();

    for suite in SigSuite::transition() {
        let tag = suite.id().to_string();
        let (pk, sk) = sig_keygen(&dir, suite, &tag);
        let sig = dir.path(&format!("{tag}.sig"));
        let out = vyra(&[
            s("sig"),
            s("sign"),
            s("--sk"),
            p(&sk),
            s("--in"),
            p(&msg),
            s("--context"),
            s("tests/cli"),
            s("--sig"),
            p(&sig),
        ]);
        assert_ok(&out, "sig sign");
        assert_eq!(fs::read(&sig).unwrap().len(), suite.encoded_signature_len());

        let verify = |input: &Path, context: Option<&str>, sig: &Path| {
            let mut args = vec![
                s("sig"),
                s("verify"),
                s("--pk"),
                p(&pk),
                s("--in"),
                p(input),
                s("--sig"),
                p(sig),
            ];
            if let Some(c) = context {
                args.push(s("--context"));
                args.push(s(c));
            }
            vyra(&args)
        };

        let out = verify(&msg, Some("tests/cli"), &sig);
        assert_ok(&out, "sig verify");
        assert!(stdout(&out).contains("signature valid"));

        assert_fails(
            &verify(&modified, Some("tests/cli"), &sig),
            1,
            "verify modified input",
        );
        assert_fails(
            &verify(&msg, Some("other"), &sig),
            1,
            "verify wrong context",
        );
        assert_fails(&verify(&msg, None, &sig), 1, "verify without context");

        let mut bytes = fs::read(&sig).unwrap();
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        let bad_sig = dir.path(&format!("{tag}.bad.sig"));
        fs::write(&bad_sig, &bytes).unwrap();
        assert_fails(
            &verify(&msg, Some("tests/cli"), &bad_sig),
            1,
            "verify tampered signature",
        );
    }
}

/// One full file-based flow for a dual post-quantum suite: keygen, sign,
/// verify; a modified input, a wrong context and a tampered signature each
/// exit 1. One signature (seconds), the rest is verification.
fn sig_flow_dual_pq(suite: SigSuite) {
    assert!(suite.is_dual_pq());
    let dir = TempDir::new(&format!("sig-{}", sig_suite_arg(suite)));
    let msg = dir.path("release.tar");
    let modified = dir.path("release-modified.tar");
    let content: Vec<u8> = (0..3000u32).map(|i| (i % 253) as u8).collect();
    fs::write(&msg, &content).unwrap();
    let mut other = content.clone();
    if let Some(b) = other.get_mut(1500) {
        *b ^= 0x01;
    }
    fs::write(&modified, &other).unwrap();

    let (pk, sk) = sig_keygen(&dir, suite, "pq");
    assert_eq!(fs::read(&pk).unwrap().len(), suite.encoded_public_key_len());
    assert_eq!(fs::read(&sk).unwrap().len(), suite.encoded_secret_key_len());
    let sig = dir.path("pq.sig");
    let out = vyra(&[
        s("sig"),
        s("sign"),
        s("--sk"),
        p(&sk),
        s("--in"),
        p(&msg),
        s("--context"),
        s("tests/cli/pq"),
        s("--sig"),
        p(&sig),
    ]);
    assert_ok(&out, "sig sign (dual PQ)");
    assert!(stdout(&out).contains(suite.name()));
    assert_eq!(fs::read(&sig).unwrap().len(), suite.encoded_signature_len());

    let verify = |input: &Path, context: &str, sig: &Path| {
        vyra(&[
            s("sig"),
            s("verify"),
            s("--pk"),
            p(&pk),
            s("--in"),
            p(input),
            s("--sig"),
            p(sig),
            s("--context"),
            s(context),
        ])
    };
    let out = verify(&msg, "tests/cli/pq", &sig);
    assert_ok(&out, "sig verify (dual PQ)");
    assert!(stdout(&out).contains(&format!("{}: signature valid", suite.name())));
    assert_fails(
        &verify(&modified, "tests/cli/pq", &sig),
        1,
        "verify modified input (dual PQ)",
    );
    assert_fails(
        &verify(&msg, "tests/cli", &sig),
        1,
        "verify wrong context (dual PQ)",
    );
    let mut bytes = fs::read(&sig).unwrap();
    if let Some(last) = bytes.last_mut() {
        *last ^= 1; // inside the SLH-DSA half
    }
    let bad_sig = dir.path("pq.bad.sig");
    fs::write(&bad_sig, &bytes).unwrap();
    assert_fails(
        &verify(&msg, "tests/cli/pq", &bad_sig),
        1,
        "verify tampered SLH-DSA half",
    );
}

#[test]
fn sig_flow_pq1() {
    sig_flow_dual_pq(SigSuite::Pq1);
}

#[test]
fn sig_flow_pq3() {
    sig_flow_dual_pq(SigSuite::Pq3);
}

#[test]
fn sig_flow_pq5() {
    sig_flow_dual_pq(SigSuite::Pq5);
}

#[test]
fn signature_suite_parsing() {
    let dir = TempDir::new("suite-parse");
    for bad in [
        "1",
        "4",
        "pq",
        "pq2",
        "PQ4",
        "17",
        "0x11",
        "VYRA-SIG-PQ1",
        "",
        "pq1x",
    ] {
        let pk = dir.path("x.pk");
        let out = vyra(&[
            s("sig"),
            s("keygen"),
            s("--suite"),
            s(bad),
            s("--pk"),
            p(&pk),
            s("--sk"),
            p(&dir.path("x.sk")),
        ]);
        assert_fails(&out, 2, &format!("--suite {bad:?}"));
        assert!(
            stderr(&out).contains("expected 2, 3, 5, pq1, pq3 or pq5"),
            "{}",
            stderr(&out)
        );
        assert!(!pk.exists(), "no key written for --suite {bad:?}");
    }
    // A KEM suite flag never accepts a signature suite name.
    let out = vyra(&[
        s("kem"),
        s("keygen"),
        s("--suite"),
        s("pq1"),
        s("--pk"),
        p(&dir.path("k.pk")),
        s("--sk"),
        p(&dir.path("k.sk")),
    ]);
    assert_fails(&out, 2, "kem keygen --suite pq1");
}

#[test]
fn seal_flow_every_suite() {
    let dir = TempDir::new("seal");
    let plain = dir.path("plain.bin");
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    fs::write(&plain, &content).unwrap();

    for suite in KemSuite::all() {
        let tag = suite.id().to_string();
        let (pk, sk) = kem_keygen(&dir, suite, &tag);
        let (_, other_sk) = kem_keygen(&dir, suite, &format!("{tag}-other"));
        let sealed = dir.path(&format!("{tag}.sealed"));
        let out = vyra(&[
            s("seal"),
            s("--pk"),
            p(&pk),
            s("--in"),
            p(&plain),
            s("--out"),
            p(&sealed),
            s("--aad"),
            s("hdr"),
        ]);
        assert_ok(&out, "seal");
        assert_eq!(
            fs::read(&sealed).unwrap().len(),
            content.len() + SealedBox::overhead(suite)
        );

        let open = |sk: &Path, aad: &str, out_name: &str| {
            let target = dir.path(out_name);
            let out = vyra(&[
                s("open"),
                s("--sk"),
                p(sk),
                s("--in"),
                p(&sealed),
                s("--out"),
                p(&target),
                s("--aad"),
                s(aad),
            ]);
            (out, target)
        };

        let (out, opened) = open(&sk, "hdr", &format!("{tag}.opened"));
        assert_ok(&out, "open");
        assert_eq!(fs::read(&opened).unwrap(), content);

        let (out, target) = open(&other_sk, "hdr", &format!("{tag}.wrongkey"));
        assert_fails(&out, 1, "open with wrong key");
        assert!(!target.exists(), "no output on failure");

        let (out, _) = open(&sk, "HDR", &format!("{tag}.wrongaad"));
        assert_fails(&out, 1, "open with wrong aad");
    }

    // A key of another suite cannot open the box either.
    let (pk1, _) = kem_keygen(&dir, KemSuite::Vyra1, "x1");
    let (_, sk3) = kem_keygen(&dir, KemSuite::Vyra3, "x3");
    let sealed = dir.path("x.sealed");
    assert_ok(
        &vyra(&[
            s("seal"),
            s("--pk"),
            p(&pk1),
            s("--in"),
            p(&plain),
            s("--out"),
            p(&sealed),
        ]),
        "seal suite 1",
    );
    let out = vyra(&[
        s("open"),
        s("--sk"),
        p(&sk3),
        s("--in"),
        p(&sealed),
        s("--out"),
        p(&dir.path("x.opened")),
    ]);
    assert_fails(&out, 1, "open with key of another suite");
}

#[test]
fn bad_arguments_fail_cleanly() {
    let cases: &[&[&str]] = &[
        &[],
        &["frobnicate"],
        &["kem"],
        &["kem", "bogus"],
        &["kem", "keygen"],
        &["kem", "keygen", "--suite", "2", "--pk", "a", "--sk", "b"],
        &["sig", "keygen", "--suite", "1", "--pk", "a", "--sk", "b"],
        &["kem", "keygen", "--suite", "3", "--pk"],
        &["kem", "encaps", "--pk", "a", "--ct", "b"],
        &[
            "sig", "verify", "--pk", "a", "--in", "b", "--sig", "c", "--bogus", "d",
        ],
        &["seal", "--pk", "a", "--pk", "b", "--in", "c", "--out", "d"],
        &["info", "extra"],
    ];
    for args in cases {
        let os: Vec<&OsStr> = args.iter().map(|a| s(a)).collect();
        assert_fails(&vyra(&os), 2, &format!("{args:?}"));
    }
}

#[test]
fn missing_truncated_and_wrong_files_fail_cleanly() {
    let dir = TempDir::new("errors");
    let (pk, sk) = kem_keygen(&dir, KemSuite::Vyra1, "k");
    let (spk, ssk) = sig_keygen(&dir, SigSuite::Vyra2, "s");
    let missing = dir.path("does-not-exist");
    let msg = dir.path("msg");
    fs::write(&msg, b"m").unwrap();

    let truncate = |src: &Path, name: &str, keep: usize| {
        let mut bytes = fs::read(src).unwrap();
        bytes.truncate(keep);
        let path = dir.path(name);
        fs::write(&path, &bytes).unwrap();
        path
    };
    let pk_len = fs::read(&pk).unwrap().len();
    let short_pk = truncate(&pk, "short.pk", pk_len - 1);
    let header_only = truncate(&pk, "header.pk", 7);
    let empty = truncate(&pk, "empty", 0);
    let sk_len = fs::read(&sk).unwrap().len();
    let short_sk = truncate(&sk, "short.sk", sk_len - 1);
    let garbage = dir.path("garbage");
    fs::write(&garbage, b"this is not a VYRA object at all").unwrap();

    let encaps = |pk: &Path, tag: &str| {
        vyra(&[
            s("kem"),
            s("encaps"),
            s("--pk"),
            p(pk),
            s("--ct"),
            p(&dir.path(&format!("{tag}.ct"))),
            s("--ss"),
            p(&dir.path(&format!("{tag}.ss"))),
        ])
    };
    assert_fails(&encaps(&missing, "a"), 3, "missing public key");
    assert_fails(&encaps(&short_pk, "b"), 3, "truncated public key");
    assert_fails(&encaps(&header_only, "c"), 3, "header-only public key");
    assert_fails(&encaps(&empty, "d"), 3, "empty public key");
    assert_fails(&encaps(&garbage, "e"), 3, "garbage public key");
    assert_fails(&encaps(&spk, "f"), 3, "signature key given as KEM key");
    assert_fails(&encaps(&sk, "g"), 3, "secret key given as public key");

    // A good encapsulation, then decapsulation with bad inputs.
    assert_ok(&encaps(&pk, "good"), "encaps");
    let ct = dir.path("good.ct");
    let ct_len = fs::read(&ct).unwrap().len();
    let short_ct = truncate(&ct, "short.ct", ct_len - 1);
    let decaps = |sk: &Path, ct: &Path, tag: &str| {
        vyra(&[
            s("kem"),
            s("decaps"),
            s("--sk"),
            p(sk),
            s("--ct"),
            p(ct),
            s("--ss"),
            p(&dir.path(&format!("{tag}.ss"))),
        ])
    };
    assert_fails(&decaps(&sk, &short_ct, "h"), 3, "truncated ciphertext");
    assert_fails(&decaps(&short_sk, &ct, "i"), 3, "truncated secret key");
    assert_fails(&decaps(&missing, &ct, "j"), 3, "missing secret key");
    assert_fails(
        &decaps(&ssk, &ct, "k"),
        3,
        "signature secret key for decaps",
    );
    let (_, sk3) = kem_keygen(&dir, KemSuite::Vyra3, "k3");
    assert_fails(&decaps(&sk3, &ct, "l"), 3, "suite mismatch");

    // Signatures.
    let sig = dir.path("m.sig");
    let sign = |sk: &Path, input: &Path, out: &Path| {
        vyra(&[
            s("sig"),
            s("sign"),
            s("--sk"),
            p(sk),
            s("--in"),
            p(input),
            s("--sig"),
            p(out),
        ])
    };
    assert_fails(&sign(&missing, &msg, &sig), 3, "missing signing key");
    assert_fails(&sign(&ssk, &missing, &sig), 3, "missing message");
    assert_fails(&sign(&sk, &msg, &sig), 3, "KEM key used for signing");
    assert_ok(&sign(&ssk, &msg, &sig), "sign");
    let sig_len = fs::read(&sig).unwrap().len();
    let short_sig = truncate(&sig, "short.sig", sig_len - 1);
    let verify = |pk: &Path, sig: &Path| {
        vyra(&[
            s("sig"),
            s("verify"),
            s("--pk"),
            p(pk),
            s("--in"),
            p(&msg),
            s("--sig"),
            p(sig),
        ])
    };
    assert_ok(&verify(&spk, &sig), "verify");
    assert_fails(&verify(&spk, &short_sig), 3, "truncated signature");
    assert_fails(&verify(&spk, &missing), 3, "missing signature");
    assert_fails(&verify(&pk, &sig), 3, "KEM key used for verify");

    let long_context = "c".repeat(256);
    let out = vyra(&[
        s("sig"),
        s("sign"),
        s("--sk"),
        p(&ssk),
        s("--in"),
        p(&msg),
        s("--context"),
        s(&long_context),
        s("--sig"),
        p(&dir.path("long.sig")),
    ]);
    assert_fails(&out, 2, "context over 255 bytes");

    // Sealed boxes.
    let sealed = dir.path("m.sealed");
    assert_ok(
        &vyra(&[
            s("seal"),
            s("--pk"),
            p(&pk),
            s("--in"),
            p(&msg),
            s("--out"),
            p(&sealed),
        ]),
        "seal",
    );
    let sealed_len = fs::read(&sealed).unwrap().len();
    let short_sealed = truncate(&sealed, "short.sealed", sealed_len - 17);
    let open = |input: &Path, tag: &str| {
        vyra(&[
            s("open"),
            s("--sk"),
            p(&sk),
            s("--in"),
            p(input),
            s("--out"),
            p(&dir.path(&format!("{tag}.opened"))),
        ])
    };
    assert_fails(&open(&short_sealed, "m"), 3, "truncated sealed box");
    assert_fails(
        &open(&header_only, "n"),
        3,
        "public key given as sealed box",
    );
    assert_fails(&open(&missing, "o"), 3, "missing sealed box");
    assert_fails(&open(&empty, "p"), 3, "empty sealed box");
}

#[test]
fn existing_outputs_are_not_overwritten_without_force() {
    let dir = TempDir::new("force");
    let (pk, sk) = kem_keygen(&dir, KemSuite::Vyra1, "a");
    let before = fs::read(&sk).unwrap();
    let args = |force: bool| {
        let mut v = vec![
            s("kem"),
            s("keygen"),
            s("--suite"),
            s("1"),
            s("--pk"),
            p(&pk),
            s("--sk"),
            p(&sk),
        ];
        if force {
            v.push(s("--force"));
        }
        vyra(&v)
    };
    let out = args(false);
    assert_fails(&out, 3, "overwrite without --force");
    assert!(stderr(&out).contains("--force"));
    assert_eq!(fs::read(&sk).unwrap(), before, "secret key file unchanged");

    assert_ok(&args(true), "overwrite with --force");
    assert_ne!(fs::read(&sk).unwrap(), before);
}
