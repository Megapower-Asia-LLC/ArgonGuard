<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Engine;

use ArgonGuard\Passwords\Phc\PhcHash;
use ArgonGuard\Passwords\Phc\PhcParser;
use ArgonGuard\Passwords\ProfileParameters;
use ArgonGuard\Passwords\ReasonCodes;
use ArgonGuard\Passwords\UnsupportedEnvironmentException;

/**
 * sodium fallback provider（生產路徑）：PHP 無原生 argon2id 但有 ext-sodium 時啟用。
 * 以自寫 parser 解出的參數 raw 重算 → hash_equals 常數時間比對（SPEC §8.1）。
 *
 * 單位換算（權威：spec/engine-units.json `php_sodium_crypto_pwhash_memlimit`）：
 * **memlimit = m(KiB) × 1024（bytes）**——off-by-1024 由雙 provider 一致測試釘死。
 *
 * 已知邊角（libsodium API 限制，文件註明）：sodium_crypto_pwhash 的 salt 固定
 * SODIUM_CRYPTO_PWHASH_SALTBYTES（16 bytes）；非 16-byte salt 的外來雜湊在本 provider
 * 無法重算 → UnsupportedEnvironmentException（不會誤回 false；V1 語意不被破壞）。
 *
 * @internal 不屬於公開 API。
 */
final class SodiumArgon2Provider implements Argon2Provider
{
    public function hashEncoded(#[\SensitiveParameter] string $password, ProfileParameters $params): string
    {
        $salt = random_bytes($params->saltBytes); // SPEC §8.2 CSPRNG
        $tag = $this->computeRaw($password, $salt, $params->m, $params->t, $params->tagBytes);

        return PhcParser::encode($params->m, $params->t, $params->p, $salt, $tag);
    }

    public function verifyParsed(#[\SensitiveParameter] string $password, string $encoded, PhcHash $parsed): bool
    {
        $tag = $this->computeRaw($password, $parsed->salt, $parsed->m, $parsed->t, strlen($parsed->tag));

        return hash_equals($parsed->tag, $tag); // 常數時間（SPEC §8.1）
    }

    /** raw tag 重算。$m 單位 KiB；內部換算 memlimit = m × 1024 bytes。 */
    public function computeRaw(
        #[\SensitiveParameter] string $password,
        string $salt,
        int $m,
        int $t,
        int $tagLen,
    ): string {
        if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            // libsodium crypto_pwhash API 僅支援 16-byte salt（見 class docblock）。
            throw new UnsupportedEnvironmentException(ReasonCodes::ARGON2ID_UNAVAILABLE);
        }

        return sodium_crypto_pwhash(
            $tagLen,
            $password,
            $salt,
            $t,                 // opslimit＝t
            $m * 1024,          // memlimit（bytes）＝m（KiB）× 1024（engine-units.json 為權威）
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );
    }
}
