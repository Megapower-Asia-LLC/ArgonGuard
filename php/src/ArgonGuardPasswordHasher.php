<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

use ArgonGuard\Passwords\Engine\Argon2Provider;
use ArgonGuard\Passwords\Engine\Argon2Providers;
use ArgonGuard\Passwords\Legacy\LegacyPasswordVerifier;
use ArgonGuard\Passwords\Phc\PhcHash;
use ArgonGuard\Passwords\Phc\PhcParser;
use ArgonGuard\Passwords\Policy\VerificationPolicy;

/**
 * ArgonGuard 密碼雜湊器（PHP 實作；ArgonGuard Spec 1.0.0）。
 *
 * 標準升級流程（SPEC §6.1）：
 * <code>
 * if ($hasher->verifyPassword($pw, $stored)) {
 *     if ($hasher->needsRehash($stored)) { store($hasher->hashPassword($pw)); }
 *     loginOk();
 * }
 * </code>
 *
 * 輸入語意（SPEC §5 I4，PHP 特例）：PHP string 即 byte string，密碼位元組原樣使用；
 * 不做（也無從做）unpaired-surrogate well-formed 檢查——該檢查僅適用於
 * UTF-16 字串語意的語言（.NET／Node）。長度限制以 bytes 計（strlen）。
 *
 * 建構期能力檢查 fail-fast：無原生 argon2id 且無 ext-sodium →
 * UnsupportedEnvironmentException（environment.argon2id_unavailable）；絕不降級 bcrypt。
 */
final readonly class ArgonGuardPasswordHasher
{
    private ProfileParameters $active;

    /** @var list<LegacyPasswordVerifier> 建構時複製，之後不可變（SPEC §6.4 L1） */
    private array $legacyVerifiers;

    private Argon2Provider $engine;

    /**
     * @param ArgonGuardProfile $profile 強度檔位（預設 Default）。
     * @param iterable<LegacyPasswordVerifier> $legacyVerifiers Legacy verifier 有序清單；建構時複製為不可變。
     */
    public function __construct(
        public ArgonGuardProfile $profile = ArgonGuardProfile::Default,
        iterable $legacyVerifiers = [],
    ) {
        $this->active = ProfileParameters::forProfile($profile);
        $copied = [];
        foreach ($legacyVerifiers as $verifier) {
            if (!$verifier instanceof LegacyPasswordVerifier) {
                throw new \InvalidArgumentException('Legacy verifier list must contain only LegacyPasswordVerifier instances.');
            }
            $copied[] = $verifier;
        }
        $this->legacyVerifiers = $copied;
        $this->engine = Argon2Providers::select(); // fail-fast（SPEC §7 UnsupportedEnvironment）
    }

    /** 以 active 檔位＋fresh 16-byte CSPRNG salt 產生 PHC encoded 雜湊（SPEC §2、§6.1）。 */
    public function hashPassword(#[\SensitiveParameter] string $password): string
    {
        self::validatePassword($password);
        $encoded = $this->engine->hashEncoded($password, $this->active);

        // 防禦性 sanity check：引擎輸出必須嚴格符合 SPEC §2 與 active 檔位（封死異常 build 的格式漂移）。
        $parsed = PhcParser::parse($encoded);
        if ($parsed->version !== VerificationPolicy::REQUIRED_VERSION
            || $parsed->m !== $this->active->m
            || $parsed->t !== $this->active->t
            || $parsed->p !== $this->active->p
            || strlen($parsed->salt) !== $this->active->saltBytes
            || strlen($parsed->tag) !== $this->active->tagBytes) {
            throw new UnsupportedEnvironmentException(ReasonCodes::ARGON2ID_UNAVAILABLE);
        }

        return $encoded;
    }

    /**
     * 驗證密碼（SPEC §6.2 dispatch）。
     * 回傳 false 只有一個意思：格式正確、政策合規的雜湊，密碼不符（V1）；其餘一律 typed error。
     */
    public function verifyPassword(#[\SensitiveParameter] string $password, string $encodedHash): bool
    {
        self::validatePassword($password);

        // §6.2 步驟 2：解析前長度預檢
        if (strlen($encodedHash) > VerificationPolicy::MAX_ENCODED_LENGTH) {
            throw new MalformedHashException(ReasonCodes::ENCODED_TOO_LONG);
        }

        // §6.2 3b 前置：演算法 token 判斷（非 argon2id 不套 argon2 嚴格文法；baseline §1）
        $algorithm = PhcParser::tryGetAlgorithm($encodedHash);
        if ($algorithm !== 'argon2id') {
            $claimed = $this->tryLegacy($password, $encodedHash);
            if ($claimed !== null) {
                return $claimed;
            }
            throw $algorithm === null
                ? new MalformedHashException(ReasonCodes::NOT_PHC)
                : new UnsupportedAlgorithmException(ReasonCodes::UNSUPPORTED_ALGORITHM);
        }

        try {
            $parsed = PhcParser::parse($encodedHash);
        } catch (MalformedHashException $e) {
            // §6.2 3b：argon2id 但嚴格文法解析失敗 → legacy；無人認領 → 原 MalformedHash
            $claimed = $this->tryLegacy($password, $encodedHash);
            if ($claimed !== null) {
                return $claimed;
            }
            throw new MalformedHashException($e->getReason());
        }

        $violation = VerificationPolicy::check($parsed);
        if ($violation !== null) {
            // §6.2 3a：out-of-policy argon2id → 顯式註冊的 legacy 才可認領（看得見的 opt-in）
            $claimed = $this->tryLegacy($password, $encodedHash);
            if ($claimed !== null) {
                return $claimed;
            }
            throw new PolicyViolationException($violation);
        }

        return $this->engine->verifyParsed($password, $encodedHash, $parsed);
    }

    /**
     * 是否需要 rehash（SPEC §6.3）：只 parse 與比對、不做任何雜湊。
     * 自寫 parser 精確比對（baseline §5）；禁用 password_needs_rehash（provider 漂移）。
     */
    public function needsRehash(string $encodedHash): bool
    {
        if (strlen($encodedHash) > VerificationPolicy::MAX_ENCODED_LENGTH) {
            throw new MalformedHashException(ReasonCodes::ENCODED_TOO_LONG);
        }

        $algorithm = PhcParser::tryGetAlgorithm($encodedHash);
        if ($algorithm !== 'argon2id') {
            // SPEC §6.3 N2：legacy 認領恆 true
            if ($this->isClaimedByLegacy($encodedHash)) {
                return true;
            }
            throw $algorithm === null
                ? new MalformedHashException(ReasonCodes::NOT_PHC)
                : new UnsupportedAlgorithmException(ReasonCodes::UNSUPPORTED_ALGORITHM);
        }

        try {
            $parsed = PhcParser::parse($encodedHash);
        } catch (MalformedHashException $e) {
            // SPEC §6.3 N3：無人認領＝資料毀損，不得折疊成 true
            if ($this->isClaimedByLegacy($encodedHash)) {
                return true;
            }
            throw $e;
        }

        // 精確參數比對（含 salt/tag 長度；任一欄位不同即 true——含「更強」的情況；baseline §5）
        return $parsed->version !== VerificationPolicy::REQUIRED_VERSION
            || $parsed->hasKeyid || $parsed->hasData
            || $parsed->m !== $this->active->m
            || $parsed->t !== $this->active->t
            || $parsed->p !== $this->active->p
            || strlen($parsed->salt) !== $this->active->saltBytes
            || strlen($parsed->tag) !== $this->active->tagBytes;
    }

    /** 依序詢問 legacy verifiers；回傳 null＝無人認領，否則第一個認領者的裁決（SPEC §6.2）。 */
    private function tryLegacy(#[\SensitiveParameter] string $password, string $encodedHash): ?bool
    {
        foreach ($this->legacyVerifiers as $verifier) {
            if ($verifier->canHandle($encodedHash)) {
                return $verifier->verify($password, $encodedHash);
            }
        }

        return null;
    }

    private function isClaimedByLegacy(string $encodedHash): bool
    {
        foreach ($this->legacyVerifiers as $verifier) {
            if ($verifier->canHandle($encodedHash)) {
                return true;
            }
        }

        return false;
    }

    /**
     * SPEC §5 輸入規則。檢查優先序（baseline §2）：well-formed → empty → too_long → NUL；
     * PHP string 為 byte 語意，well-formed（unpaired surrogate）檢查不適用，其餘順序相同。
     */
    private static function validatePassword(#[\SensitiveParameter] string $password): void
    {
        if ($password === '') {
            throw new InvalidInputException(ReasonCodes::PASSWORD_EMPTY);
        }
        if (strlen($password) > 1024) {
            throw new InvalidInputException(ReasonCodes::PASSWORD_TOO_LONG);
        }
        if (str_contains($password, "\0")) {
            throw new InvalidInputException(ReasonCodes::PASSWORD_CONTAINS_NUL);
        }
    }
}
