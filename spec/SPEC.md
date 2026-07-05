# ArgonGuard Specification

**Spec version:** 1.0.0 (frozen constants; see §9 for versioning rules)
**Status:** Normative
**Consensus record:** design doc `docs/specs/2026-07-05-argonguard-design.md` (Perplexity review round 3: approved)

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "MAY" in this document are to be interpreted as described in RFC 2119.

Machine-readable authoritative artifacts (this prose defers to them wherever they overlap):

| Artifact | Authority over |
|---|---|
| `reason-codes.json` | exact reason-code strings |
| `engine-units.json` | memory-unit mapping, profile constants, frontier/ceiling constants |
| `vectors/v1/*.json` + `MANIFEST.sha256` | conformance behavior (frozen; append-only) |
| `harness-contract.json` | dev-harness I/O protocol |

## 1. Scope

ArgonGuard is a cross-language password hashing component. Implementations exist for .NET, Node.js, Python, and PHP. Every implementation MUST produce and verify interchangeable output: a hash produced by any implementation MUST verify on every other implementation.

The only supported algorithm is **Argon2id** (RFC 9106). Implementations MUST NOT produce hashes with any other algorithm. Legacy algorithms are verify-only via the extension point in §6.4.

## 2. Encoded hash format (generation)

The encoded form is the standard PHC string format:

```
$argon2id$v=19$m=<m>,t=<t>,p=1$<salt-b64>$<tag-b64>
```

Generation rules (all MUST):

- G1. Algorithm identifier is exactly `argon2id`.
- G2. The version field `v=19` MUST be present and MUST be emitted explicitly.
- G3. Parameters MUST appear in exactly the order `m`, `t`, `p`.
- G4. `keyid` and `data` fields MUST NOT be emitted.
- G5. Salt and tag are Base64 (RFC 4648 §4 standard alphabet, **no padding**, not base64url).
- G6. Salt MUST be exactly 16 bytes, freshly generated per hash from the platform CSPRNG (see §8.2). The public API MUST NOT accept a caller-provided salt.
- G7. Tag (hash output) MUST be exactly 32 bytes.
- G8. `p` is always `1` (ADR 0002).
- G9. Typical encoded length is 97–98 characters (depends on the digit count of `m`). Storage columns SHOULD be at least 128 characters. The specification maximum is 512 characters (§4, C5).

## 3. Profiles

Profiles are a closed set, frozen per spec version. The public API MUST NOT expose any numeric Argon2 parameter; callers select a profile only.

| Profile | m (KiB) | t | p | salt | tag |
|---|---|---|---|---|---|
| `default` | 19456 | 2 | 1 | 16 B | 32 B |
| `high` | 65536 | 2 | 1 | 16 B | 32 B |
| `highest` | 131072 | 2 | 1 | 16 B | 32 B |

- P1. `default` MUST equal (m=19456, t=2, p=1) — this is a permanent sentinel; CI MUST assert it.
- P2. Modifying an existing profile's parameters is FORBIDDEN. Strengthening means adding a new profile name (spec MINOR).
- P3. Adding a profile MUST keep it within the verification ceiling (§4), so that older verifiers remain forward-compatible.

## 4. Verification policy

Verification applies the following checks to a parsed argon2id PHC string, in this order conceptually (exact dispatch in §6.2). Constants are authoritative in `engine-units.json`.

**Floor — OWASP frontier (frozen table, verified against OWASP Password Storage Cheat Sheet on 2026-07-05):**

| t | minimum m (KiB) |
|---|---|
| 1 | 47104 |
| 2 | 19456 |
| 3 | 12288 |
| 4 | 9216 |
| ≥5 | 7168 |

- F1. (m, t) MUST lie on or above the frontier; otherwise `PolicyViolation` / `policy_violation.below_owasp_frontier`.
- F2. `v` MUST be present and equal `19`; missing → `policy_violation.missing_version`; other value → `policy_violation.unsupported_version`.
- F3. `p` MUST equal 1 → otherwise `policy_violation.p_not_one`.
- F4. Salt length MUST be ≥16 and ≤64 bytes; tag length MUST be ≥32 and ≤128 bytes → otherwise `policy_violation.salt_length_out_of_range` / `policy_violation.tag_length_out_of_range`.
- F5. `keyid` / `data` fields, if present, are rejected → `policy_violation.keyid_not_allowed` / `policy_violation.data_not_allowed`.

**Ceiling (denial-of-service protection against tampered stores):**

- C1. `m` MUST be ≤ 262144 KiB (256 MiB) → otherwise `policy_violation.m_above_ceiling`.
- C2. `t` MUST be ≤ 8 → otherwise `policy_violation.t_above_ceiling`.
- C3–C4. Salt/tag upper bounds as in F4.
- C5. The encoded string MUST be ≤ 512 characters, checked **before** any parsing; longer input → `MalformedHash` / `malformed.encoded_too_long`.

**Parsing strictness:**

- S1. Parameters in any order other than `m,t,p` → `malformed.params_out_of_order`.
- S2. Base64 with padding (`=`), base64url alphabet, or otherwise invalid → `malformed.bad_base64`. Verification MUST reject padded Base64 even though it is decodable.
- S3. Any string not matching the strict grammar → `malformed.not_phc`.
- S4. Numeric fields MUST be parsed with overflow protection; values exceeding the ceiling range MUST NOT wrap silently.

Only after all policy checks pass may the implementation recompute the tag with the parameters from the string and compare it in constant time (§8.1).

## 5. Password input

- I1. At spec level the password is a **byte string**. String-typed APIs MUST encode as UTF-8 with no trimming, no case folding, and **no Unicode normalization** (applications SHOULD normalize to NFC at their input boundary; ArgonGuard MUST NOT silently rewrite input).
- I2. Length limits are counted in **UTF-8 encoded bytes**: minimum 1, maximum 1024. Empty → `invalid_input.password_empty`; longer → `invalid_input.password_too_long`.
- I3. The password MUST NOT contain U+0000 → `invalid_input.password_contains_nul`.
- I4. String inputs MUST be well-formed Unicode; unpaired surrogates MUST be rejected → `invalid_input.password_not_well_formed` (.NET: throwing `UTF8Encoding`; Node: `String.prototype.isWellFormed()`; Python: `str.encode` raises naturally; PHP strings are byte strings and are used as-is).
- I5. Hash and Verify MUST apply identical input rules.

## 6. Operations

### 6.1 Core API

```
hashPassword(password) -> encoded        # active profile + fresh 16-byte CSPRNG salt
verifyPassword(password, encoded) -> bool
needsRehash(encoded) -> bool             # parse-and-compare only; performs no hashing
```

Naming follows language conventions (`HashPassword` / `hash_password` / `hashPassword`). Node.js exposes `hashPassword`/`verifyPassword` as Promise-based async (real background thread); `needsRehash` is synchronous. .NET, Python and PHP are synchronous in v1 (no fake async). This cross-language shape difference is intentional and is not drift.

The canonical upgrade flow (documentation MUST include it):

```
if verifyPassword(pw, stored):
    if needsRehash(stored): store(hashPassword(pw))
    loginOk()
```

### 6.2 Verify dispatch (normative order)

```
1. Input checks (§5).
2. length(encoded) > 512  -> MalformedHash(malformed.encoded_too_long)
3. Strict PHC parse:
   a. Parse OK and algorithm == argon2id:
      - policy checks (§4) pass -> recompute tag -> constant-time compare -> bool
      - policy checks fail -> ask registered legacy verifiers in order (canHandle);
        first claimer decides; no claimer -> PolicyViolation (with the specific reason code)
   b. Parse fails, or algorithm != argon2id:
      - ask registered legacy verifiers in order; claimer decides
      - no claimer: not argon2id -> UnsupportedAlgorithm(unsupported.algorithm);
                    otherwise   -> MalformedHash (with the specific reason code)
```

- V1. `verifyPassword` returning `false` has exactly one meaning: *well-formed, policy-compliant hash; password does not match*. All other conditions MUST surface as typed errors and MUST NOT be masked as `false`.
- V2. In-policy argon2id always takes the core path; out-of-policy argon2id (e.g. p>1 legacy stores) can only be accepted through an explicitly registered legacy verifier — a visible opt-in, never a default.

### 6.3 needsRehash semantics

`needsRehash(encoded) == true` iff the hash was **not** produced with the exact parameters of the current active profile (any field differs — including parameters *stronger* than active; semantics equivalent to PHP `password_needs_rehash` and argon2-cffi `check_needs_rehash`; the store converges to a single parameter set).

- N1. All implementations compute this with their own spec-layer parser; they MUST NOT delegate to the underlying engine's rehash helper (eliminates provider drift).
- N2. Strings claimed by a registered legacy verifier → always `true`.
- N3. Unparseable strings claimed by nobody → throw `MalformedHash` (data corruption must not be folded into `true`).
- N4. `needsRehash` performs no hashing and has no DoS surface.

### 6.4 Configuration and legacy extension point

- L1. Hasher construction takes: active profile (default: `default`) and an **immutable ordered list** of legacy verifiers. Runtime registration MUST be impossible (API shape, not convention).
- L2. `LegacyPasswordVerifier` interface: `canHandle(encoded) -> bool` (cheap prefix test) and `verify(password, encoded) -> bool`.
- L3. The core ships **no** legacy algorithm implementations; documentation provides complete example code (e.g. bcrypt).
- L4. v1 exposes no free parameter injection of any kind.

## 7. Errors

Five categories; every error carries a machine-readable reason code. The exact strings are authoritative in `reason-codes.json`; implementations MUST emit them bit-identically. Error messages MUST NOT contain the password, the salt, or the tag (OWASP Error Handling Cheat Sheet; SEC-006).

| Category | Meaning |
|---|---|
| `MalformedHash` | not strictly parseable / too long / bad base64 / params out of order |
| `UnsupportedAlgorithm` | non-argon2id, unclaimed |
| `PolicyViolation` | parseable argon2id outside policy, unclaimed |
| `InvalidInput` | password violates §5 |
| `UnsupportedEnvironment` | runtime cannot provide argon2id (fail-fast; PHP MUST NOT fall back to bcrypt) |

## 8. Security requirements

- 8.1 **Constant-time comparison.** Tag comparison MUST use a fixed-time primitive: .NET `CryptographicOperations.FixedTimeEquals` (net8.0) / structural XOR-accumulate polyfill (netstandard2.0; no early return, full-length loop, `NoInlining|NoOptimization`); Node `crypto.timingSafeEqual`; Python `hmac.compare_digest`; PHP `hash_equals`.
- 8.2 **CSPRNG.** Salt sources: .NET `RandomNumberGenerator`; Node `crypto.randomBytes`; Python `os.urandom` (via argon2-cffi); PHP `random_bytes`.
- 8.3 **User-enumeration mitigation (informative).** `vectors/v1/dummy-hashes.json` provides one canonical dummy hash per profile; applications SHOULD run an equal-time dummy verify when the account does not exist (also recommended by the OWASP Authentication Cheat Sheet). This mitigates only account-existence timing.
- 8.4 **Memory zeroing** is best-effort and NOT guaranteed (documented non-goal).
- 8.5 Implementations MUST keep the Argon2 engine behind an internal provider boundary; the engine type MUST NOT leak into the public API.
- 8.6 **No logging.** The library itself MUST NOT log. Nothing the library emits (errors, reason codes) may carry passwords, salts, or tags, so application logs cannot leak them through ArgonGuard (OWASP Logging Cheat Sheet). Documentation MUST advise applications to log only verify success/failure and timestamps.

## 9. Versioning

- The spec version uses SemVer. MINOR: new profile / new vector class / ceiling adjustment / frontier update following OWASP. PATCH: editorial.
- Every implementation exposes a `SPEC_VERSION` constant equal to the implemented spec version, and package metadata declares `Implements ArgonGuard Spec X.Y`.
- Frozen vectors are append-only. A defective frozen vector is corrected by creating `vectors/v2/` with a new PROVENANCE record — never by editing `v1/` (which would silently re-green downstream conformance).
- Normative changes to this document require: spec version bump, master-plan revision + re-review, and re-run of all language conformance suites.

## 10. Conformance

An implementation is conformant iff:

1. It passes **all** frozen vectors in `vectors/v1/` (deterministic, verify, reject, needs-rehash, input-limits) with byte-identical outputs and exact reason codes.
2. Its dev harness passes `harness-contract.json`.
3. It emits reason codes bit-identical to `reason-codes.json`.
4. Its unit-conversion assertions compare against `engine-units.json` values.
5. It participates green in the 4×4 cross-language round-trip matrix.

Vector provenance: deterministic vectors are generated by two independent toolchains (argon2 reference CLI × argon2-cffi) and byte-for-byte compared before freezing; ArgonGuard implementations MUST NOT be used as a vector source. See `vectors/v1/PROVENANCE.md` for underlying-implementation independence notes and the third-implementation spot-check.

## Appendix A. Security requirement traceability (OWASP / ASVS)

Source: Megapower OWASP standards note (2026-07-05); requirement template explicitly authored for inclusion in ArgonGuard.

| ID | Requirement | OWASP / ASVS reference | Spec clause |
|---|---|---|---|
| SEC-001 | Password hashing MUST use Argon2id | ASVS V6.4.1; Password Storage CS | §1 |
| SEC-002 | Memory ≥ 19 MiB, iterations ≥ 2 (as OWASP-equivalent floor) | Password Storage CS | §3 P1, §4 frontier |
| SEC-003 | Unique random salt per password, ≥16 bytes | ASVS V2.4.2 | §2 G6 |
| SEC-004 | Hash comparison MUST be constant-time | ASVS V6.4.2 | §8.1 |
| SEC-005 | MUST support needsRehash for progressive upgrade | ASVS V2.4.4 | §6.3 |
| SEC-006 | Exception messages MUST NOT contain salt or hash values | Error Handling CS | §7 |
| SEC-007 | Password input MUST have a sane maximum length | Input Validation CS | §5 I2 |

Adversarial-review index (Top 10 A02/A05/A07/A08/A09) and boundary-case checklist from the same note are inputs to milestone M5.
