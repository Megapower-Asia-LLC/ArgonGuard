<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\ArgonGuardPasswordHasher;
use ArgonGuard\Passwords\ArgonGuardProfile;
use ArgonGuard\Passwords\Legacy\LegacyPasswordVerifier;
use PHPUnit\Framework\TestCase;

/**
 * README 範例的實跑版本（文件與 CI 同源，防止 Quickstart／遷移範例腐化）。
 * 這裡每個測試對應 README 的一段可複製貼上程式碼；若簽章或行為變更，此測試會先變紅。
 */
final class QuickstartExampleTest extends TestCase
{
    /** README「Quickstart」段的最小登入流程：hashPassword → verifyPassword → needsRehash。 */
    public function testQuickstartLoginFlow(): void
    {
        $password = 'correct horse battery staple';

        $hasher = new ArgonGuardPasswordHasher();               // 預設 Default 檔位（m=19456 KiB, t=2, p=1）

        // 註冊：以 active 檔位＋fresh 16-byte CSPRNG salt 產生 PHC 字串
        $stored = $hasher->hashPassword($password);
        self::assertStringStartsWith('$argon2id$v=19$m=19456,t=2,p=1$', $stored);
        self::assertGreaterThanOrEqual(97, strlen($stored));
        self::assertLessThanOrEqual(98, strlen($stored));

        // 登入成功路徑
        $loggedIn = false;
        if ($hasher->verifyPassword($password, $stored)) {
            if ($hasher->needsRehash($stored)) {
                $stored = $hasher->hashPassword($password);
            }
            $loggedIn = true;
        }
        self::assertTrue($loggedIn);

        // 剛以 active 檔位產生的雜湊不需 rehash
        self::assertFalse($hasher->needsRehash($stored));

        // verifyPassword 回 false 只有一個意思：密碼不符
        self::assertFalse($hasher->verifyPassword('wrong password', $stored));
    }

    /** README「rehash-on-login 升級」：舊檔位雜湊登入後自動收斂到 active 檔位。 */
    public function testRehashOnLoginUpgrade(): void
    {
        $password = 'correct horse battery staple';

        // active 檔位升級成 Highest，資料庫裡卻是舊的 Default 雜湊
        $active = new ArgonGuardPasswordHasher(ArgonGuardProfile::Highest);
        $stored = (new ArgonGuardPasswordHasher(ArgonGuardProfile::Default))->hashPassword($password);

        self::assertTrue($active->verifyPassword($password, $stored)); // 舊雜湊仍驗得過
        self::assertTrue($active->needsRehash($stored));               // 但參數不是 active → 需升級

        // 登入成功後 rehash
        $rehashed = null;
        if ($active->verifyPassword($password, $stored)) {
            if ($active->needsRehash($stored)) {
                $rehashed = $active->hashPassword($password);
            }
        }

        self::assertNotNull($rehashed);
        self::assertStringStartsWith('$argon2id$v=19$m=131072,t=2,p=1$', $rehashed);
        self::assertFalse($active->needsRehash($rehashed));            // 收斂完成
        self::assertTrue($active->verifyPassword($password, $rehashed));
    }

    /** README「舊系統遷移」：注入 BcryptLegacyVerifier，登入後把 bcrypt 使用者升級到 argon2id。 */
    public function testBcryptMigrationExample(): void
    {
        $password = 'correct horse battery staple';

        // 模擬既有 bcrypt 儲存庫的一筆舊雜湊
        $stored = password_hash($password, PASSWORD_BCRYPT);
        self::assertStringStartsWith('$2y$', $stored);

        // 建構時注入 legacy verifier（清單即刻複製為不可變）
        $hasher = new ArgonGuardPasswordHasher(
            ArgonGuardProfile::Default,
            [new BcryptLegacyVerifier()],
        );

        // legacy 命中的字串 needsRehash() 恆為 true（SPEC §6.3 N2）
        self::assertTrue($hasher->needsRehash($stored));

        $rehashed = null;
        if ($hasher->verifyPassword($password, $stored)) {   // 走 legacy 路徑驗證 bcrypt
            if ($hasher->needsRehash($stored)) {
                $rehashed = $hasher->hashPassword($password); // 升級成 argon2id
            }
        }

        self::assertNotNull($rehashed);
        self::assertStringStartsWith('$argon2id$v=19$', $rehashed);
        self::assertFalse($hasher->needsRehash($rehashed));            // 已收斂到 active 檔位
        self::assertTrue($hasher->verifyPassword($password, $rehashed));
        self::assertFalse($hasher->verifyPassword('wrong password', $stored)); // 錯密碼走 legacy 亦回 false
    }
}

/**
 * README「舊系統遷移」段的完整 bcrypt legacy verifier 範例（此處與文件逐字對應）。
 * 核心不內建任何 legacy 演算法；只能在建構時注入（SPEC §6.4）。
 */
final class BcryptLegacyVerifier implements LegacyPasswordVerifier
{
    public function canHandle(string $encodedHash): bool
    {
        return str_starts_with($encodedHash, '$2y$')
            || str_starts_with($encodedHash, '$2b$')
            || str_starts_with($encodedHash, '$2a$');
    }

    public function verify(#[\SensitiveParameter] string $password, string $encodedHash): bool
    {
        return password_verify($password, $encodedHash);
    }
}
