<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Engine;

use ArgonGuard\Passwords\ReasonCodes;
use ArgonGuard\Passwords\UnsupportedEnvironmentException;

/**
 * 建構期能力檢查（fail-fast）：
 * 1. password_algos() 有 argon2id → 標準 provider（原生 password_hash/password_verify）
 * 2. 否則有 ext-sodium → sodium fallback provider
 * 3. 都沒有 → UnsupportedEnvironmentException（environment.argon2id_unavailable）
 * 絕不降級 bcrypt（SPEC §7 UnsupportedEnvironment）。
 *
 * @internal 不屬於公開 API。
 */
final class Argon2Providers
{
    private function __construct()
    {
    }

    public static function select(): Argon2Provider
    {
        $sodiumAvailable = extension_loaded('sodium') && defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13');

        // CI-only（nightly sodium-only conformance）：雙重門檻——除環境變數外，還要求
        // 測試 bootstrap 定義的 ARGONGUARD_TESTING 常數。生產部署環境即使誤設/被設 env
        // 也不會生效（避免 CWE-489 型選擇性可用性面）。兩 provider 皆通過同一組凍結向量。
        if ($sodiumAvailable
            && defined('ARGONGUARD_TESTING')
            && getenv('ARGONGUARD_TEST_FORCE_PROVIDER') === 'sodium'
        ) {
            return new SodiumArgon2Provider();
        }

        if (in_array('argon2id', password_algos(), true)) {
            return new NativeArgon2Provider();
        }
        if ($sodiumAvailable) {
            return new SodiumArgon2Provider();
        }

        throw new UnsupportedEnvironmentException(ReasonCodes::ARGON2ID_UNAVAILABLE);
    }
}
