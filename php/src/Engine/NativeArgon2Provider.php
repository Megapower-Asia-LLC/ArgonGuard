<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Engine;

use ArgonGuard\Passwords\Phc\PhcHash;
use ArgonGuard\Passwords\ProfileParameters;
use ArgonGuard\Passwords\ReasonCodes;
use ArgonGuard\Passwords\UnsupportedEnvironmentException;

/**
 * 標準 provider：原生 password_hash / password_verify（PASSWORD_ARGON2ID）。
 * 單位：memory_cost＝KiB（spec/engine-units.json `php_password_hash_memory_cost`）、
 * time_cost＝迭代、threads＝p。salt 由 PHP 內部 CSPRNG 產生（等同 random_bytes；SPEC §8.2）。
 *
 * 已知邊角（文件註明）：若 PHP 的 argon2id 是以 libsodium 提供（編譯時無 libargon2、
 * 以 sodium 補位的 build），password_verify 只支援 16-byte salt／32-byte tag 的雜湊；
 * 主流發行版（Homebrew/apt/官方 Docker）皆為 libargon2-backed，無此限制。
 *
 * @internal 不屬於公開 API。
 */
final class NativeArgon2Provider implements Argon2Provider
{
    public function hashEncoded(#[\SensitiveParameter] string $password, ProfileParameters $params): string
    {
        $encoded = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => $params->m,   // KiB（engine-units.json 為權威）
            'time_cost' => $params->t,
            'threads' => $params->p,
        ]);
        if (!is_string($encoded) || !str_starts_with($encoded, '$argon2id$v=19$')) {
            throw new UnsupportedEnvironmentException(ReasonCodes::ARGON2ID_UNAVAILABLE);
        }

        return $encoded;
    }

    public function verifyParsed(#[\SensitiveParameter] string $password, string $encoded, PhcHash $parsed): bool
    {
        // 已通過嚴格解析與政策檢查；password_verify 以字串中的參數重算並常數時間比對。
        return password_verify($password, $encoded);
    }
}
