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
        if (in_array('argon2id', password_algos(), true)) {
            return new NativeArgon2Provider();
        }
        if (extension_loaded('sodium') && defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13')) {
            return new SodiumArgon2Provider();
        }

        throw new UnsupportedEnvironmentException(ReasonCodes::ARGON2ID_UNAVAILABLE);
    }
}
