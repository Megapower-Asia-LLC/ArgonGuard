<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Legacy;

/**
 * Legacy 演算法 verify-only 擴充點（SPEC §6.4）。
 * 核心不內建任何 legacy 實作；只能在建構 ArgonGuardPasswordHasher 時以有序清單注入，
 * 建構後不可變（無 runtime 註冊）。
 */
interface LegacyPasswordVerifier
{
    /** 便宜的前綴測試：此 verifier 是否認領該 encoded 字串。 */
    public function canHandle(string $encodedHash): bool;

    /** 驗證密碼。僅在 canHandle() 回 true 時被呼叫；第一個認領者裁決。 */
    public function verify(#[\SensitiveParameter] string $password, string $encodedHash): bool;
}
