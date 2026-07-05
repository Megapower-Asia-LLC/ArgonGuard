<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\ArgonGuardProfile;
use ArgonGuard\Passwords\Engine\SodiumArgon2Provider;
use ArgonGuard\Passwords\Phc\PhcParser;
use ArgonGuard\Passwords\ProfileParameters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * 雙 provider 一致測試（off-by-1024 專門測試）：
 * 逐筆 deterministic 向量證明 native password_verify（memory_cost＝KiB）與
 * sodium_crypto_pwhash（memlimit＝bytes＝m×1024）落在同一參數點上。
 * 單位權威：spec/engine-units.json。
 */
final class DualProviderConsistencyTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function deterministicIds(): iterable
    {
        foreach (VectorData::entries('deterministic.json') as $entry) {
            yield $entry['id'] => [$entry['id']];
        }
    }

    /** (1) native 路徑：password_verify 對凍結向量必須為 true。 */
    #[DataProvider('deterministicIds')]
    public function testNativePasswordVerifyTrue(string $id): void
    {
        $e = VectorData::entry('deterministic.json', $id);
        self::assertTrue(password_verify(VectorData::hex($e['passwordHex']), $e['encoded']));
    }

    /**
     * (2) sodium 路徑：raw 重算 tag 必須與向量 encoded 內解出的 tag bytes 相同
     * （證明 KiB→bytes ×1024 換算正確），且以自寫 encoder 重組後與向量 encoded byte-identical。
     */
    #[DataProvider('deterministicIds')]
    public function testSodiumRawRecomputeMatchesFrozenTag(string $id): void
    {
        $e = VectorData::entry('deterministic.json', $id);
        $password = VectorData::hex($e['passwordHex']);
        $salt = VectorData::hex($e['saltHex']);
        $parsed = PhcParser::parse($e['encoded']);

        $provider = new SodiumArgon2Provider();
        $raw = $provider->computeRaw($password, $salt, $e['m'], $e['t'], $e['tagLen']);

        self::assertSame($parsed->tag, $raw, "sodium raw tag mismatch for {$id} (off-by-1024?)");
        self::assertSame(
            $e['encoded'],
            PhcParser::encode($e['m'], $e['t'], $e['p'], $salt, $raw),
            "re-encoded string not byte-identical for {$id}",
        );
        // verifyParsed 端到端（sodium 生產路徑）
        self::assertTrue($provider->verifyParsed($password, $e['encoded'], $parsed));
    }

    /** (3) 上下界常數斷言（權威值取自 spec/engine-units.json sodiumBoundsAssertions）。 */
    public function testSodiumBoundsAssertions(): void
    {
        $units = VectorData::engineUnits();
        $bounds = $units['verificationPolicy']['sodiumBoundsAssertions'];
        $frontierMinBytes = $bounds['frontier_min_memlimit_bytes'];
        $ceilingBytes = $bounds['ceiling_memlimit_bytes'];

        // 換算本身對照權威值（不得本地重算後自我印證）
        self::assertSame($frontierMinBytes, 7168 * 1024);
        self::assertSame($ceilingBytes, 262144 * 1024);

        // PHP ext-sodium 未暴露 *_MIN/_MAX 常數；有定義用常數，否則用 libsodium ABI 文件值
        $memlimitMin = defined('SODIUM_CRYPTO_PWHASH_MEMLIMIT_MIN') ? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MIN : 8192;
        $memlimitMax = defined('SODIUM_CRYPTO_PWHASH_MEMLIMIT_MAX') ? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MAX : 4398046510080;
        $opslimitMin = defined('SODIUM_CRYPTO_PWHASH_OPSLIMIT_MIN') ? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MIN : 1;
        $opslimitMax = defined('SODIUM_CRYPTO_PWHASH_OPSLIMIT_MAX') ? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MAX : 4294967295;

        self::assertGreaterThanOrEqual($memlimitMin, $frontierMinBytes, '7168*1024 must be >= MEMLIMIT_MIN');
        self::assertLessThanOrEqual($memlimitMax, $ceilingBytes, '262144*1024 must be <= MEMLIMIT_MAX');
        self::assertGreaterThanOrEqual($opslimitMin, 1, 't=1 must be >= OPSLIMIT_MIN');
        self::assertLessThanOrEqual($opslimitMax, 8, 't=8 must be <= OPSLIMIT_MAX');

        // 行為印證：frontier 最小 memlimit 在 t 邊界 [1, 8] 實際可執行（防常數與行為漂移）
        $salt = str_repeat("\x00", SODIUM_CRYPTO_PWHASH_SALTBYTES);
        foreach ([1, 8] as $t) {
            $out = sodium_crypto_pwhash(32, 'probe', $salt, $t, $frontierMinBytes, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            self::assertSame(32, strlen($out));
        }
    }

    /** profile 常數 vs engine-units.json 權威值（SPEC §10 conformance 條件 4）。 */
    public function testProfileConstantsMatchEngineUnits(): void
    {
        $units = VectorData::engineUnits();
        self::assertSame('KiB', $units['units']['php_password_hash_memory_cost']['unit']);
        self::assertSame('bytes', $units['units']['php_sodium_crypto_pwhash_memlimit']['unit']);

        $profiles = [
            'default' => ArgonGuardProfile::Default,
            'high' => ArgonGuardProfile::High,
            'highest' => ArgonGuardProfile::Highest,
        ];
        foreach ($profiles as $name => $profile) {
            $expected = $units['profiles'][$name];
            $actual = ProfileParameters::forProfile($profile);
            self::assertSame($expected['m_kib'], $actual->m, "{$name}.m");
            self::assertSame($expected['t'], $actual->t, "{$name}.t");
            self::assertSame($expected['p'], $actual->p, "{$name}.p");
            self::assertSame($expected['saltBytes'], $actual->saltBytes, "{$name}.saltBytes");
            self::assertSame($expected['tagBytes'], $actual->tagBytes, "{$name}.tagBytes");
            self::assertSame($expected['sodium_memlimit_bytes'], $actual->m * 1024, "{$name}.sodium_memlimit_bytes");
        }
    }
}
