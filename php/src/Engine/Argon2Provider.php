<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Engine;

use ArgonGuard\Passwords\Phc\PhcHash;
use ArgonGuard\Passwords\ProfileParameters;

/**
 * Argon2 引擎邊界（SPEC §8.5）：引擎型別不得洩漏到公開 API。
 *
 * @internal 不屬於公開 API。
 */
interface Argon2Provider
{
    /** 以 profile 參數雜湊，回傳完整 PHC encoded 字串（fresh CSPRNG salt；SPEC §2 G6）。 */
    public function hashEncoded(#[\SensitiveParameter] string $password, ProfileParameters $params): string;

    /**
     * 以字串中解析出的參數重算 tag 並以常數時間比對（SPEC §4 末段、§8.1）。
     * 前置條件：$parsed 已通過全部政策檢查。回傳 false 僅表示密碼不符。
     */
    public function verifyParsed(#[\SensitiveParameter] string $password, string $encoded, PhcHash $parsed): bool;
}
