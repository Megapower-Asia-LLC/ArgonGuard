<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\ArgonGuardException;
use ArgonGuard\Passwords\ArgonGuardPasswordHasher;
use ArgonGuard\Passwords\Legacy\LegacyPasswordVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** 凍結向量 conformance（SPEC §10）。任一紅燈＝不合規。 */
final class ConformanceTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    private static function ids(string $file): iterable
    {
        foreach (VectorData::entries($file) as $entry) {
            yield $entry['id'] => [$entry['id']];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function deterministicIds(): iterable
    {
        return self::ids('deterministic.json');
    }

    /** @return iterable<string, array{string}> */
    public static function verifyIds(): iterable
    {
        return self::ids('verify.json');
    }

    /** @return iterable<string, array{string}> */
    public static function rejectIds(): iterable
    {
        return self::ids('reject.json');
    }

    /** @return iterable<string, array{string}> */
    public static function needsRehashIds(): iterable
    {
        return self::ids('needs-rehash.json');
    }

    /** @return iterable<string, array{string}> */
    public static function inputLimitIds(): iterable
    {
        return self::ids('input-limits.json');
    }

    #[DataProvider('deterministicIds')]
    public function testDeterministicVerifiesTrue(string $id): void
    {
        $e = VectorData::entry('deterministic.json', $id);
        $hasher = new ArgonGuardPasswordHasher();
        self::assertTrue($hasher->verifyPassword(VectorData::hex($e['passwordHex']), $e['encoded']));
    }

    #[DataProvider('verifyIds')]
    public function testVerifyMatchesExpected(string $id): void
    {
        $e = VectorData::entry('verify.json', $id);
        $hasher = new ArgonGuardPasswordHasher();
        self::assertSame(
            $e['expected'],
            $hasher->verifyPassword(VectorData::hex($e['passwordHex']), $e['encoded']),
        );
    }

    #[DataProvider('rejectIds')]
    public function testRejectThrowsExactErrorAndReason(string $id): void
    {
        $e = VectorData::entry('reject.json', $id);
        $hasher = new ArgonGuardPasswordHasher();
        try {
            $hasher->verifyPassword(VectorData::hex($e['passwordHex']), $e['encoded']);
            self::fail("expected {$e['expectedError']} for {$id}");
        } catch (ArgonGuardException $ex) {
            self::assertInstanceOf(VectorData::errorClass($e['expectedError']), $ex);
            self::assertSame($e['expectedReason'], $ex->getReason());
        }
    }

    #[DataProvider('needsRehashIds')]
    public function testNeedsRehashMatchesTruthTable(string $id): void
    {
        $e = VectorData::entry('needs-rehash.json', $id);
        $legacy = $e['legacyRegistered'] ? [new FakeBcryptClaimer()] : [];
        $hasher = new ArgonGuardPasswordHasher(VectorData::profile($e['activeProfile']), $legacy);

        if (is_bool($e['expected'])) {
            self::assertSame($e['expected'], $hasher->needsRehash($e['encoded']));

            return;
        }

        try {
            $hasher->needsRehash($e['encoded']);
            self::fail("expected {$e['expected']['error']} for {$id}");
        } catch (ArgonGuardException $ex) {
            self::assertInstanceOf(VectorData::errorClass($e['expected']['error']), $ex);
            self::assertSame($e['expected']['reason'], $ex->getReason());
        }
    }

    #[DataProvider('inputLimitIds')]
    public function testInputLimitsMatchExpected(string $id): void
    {
        $e = VectorData::entry('input-limits.json', $id);
        $hasher = new ArgonGuardPasswordHasher();

        if (isset($e['refA'])) {
            // NFC vs NFD：兩筆 deterministic 向量的 encoded 必須不同（無 Unicode 正規化）
            $a = VectorData::entry('deterministic.json', $e['refA'])['encoded'];
            $b = VectorData::entry('deterministic.json', $e['refB'])['encoded'];
            self::assertNotSame($a, $b);

            return;
        }

        if ($e['appliesTo'] === 'string-apis') {
            // il-surrogate：unpaired surrogate 檢查僅適用 UTF-16 字串語意的語言（.NET/Node）；
            // PHP string 為 byte 語意（SPEC §5 I4），此案例不適用 → 跳過並註明。
            self::markTestSkipped('PHP byte-string semantics: surrogate well-formedness check not applicable (SPEC §5 I4).');
        }

        $password = VectorData::hex($e['passwordHex']);

        if ($e['expected'] === 'ok') {
            $encoded = $hasher->hashPassword($password);
            self::assertTrue($hasher->verifyPassword($password, $encoded));

            return;
        }

        // hash 與 verify 必須套用相同輸入規則（SPEC §5 I5）
        foreach (['hashPassword', 'verifyPassword'] as $op) {
            try {
                $op === 'hashPassword'
                    ? $hasher->hashPassword($password)
                    : $hasher->verifyPassword($password, VectorData::entry('deterministic.json', 'det-ascii-default')['encoded']);
                self::fail("expected {$e['expected']['error']} for {$id} via {$op}");
            } catch (ArgonGuardException $ex) {
                self::assertInstanceOf(VectorData::errorClass($e['expected']['error']), $ex);
                self::assertSame($e['expected']['reason'], $ex->getReason());
            }
        }
    }
}

/** needs-rehash 向量的 legacyRegistered=true 認領器（canHandle=$2b$ 前綴、verify=false；與向量語意一致）。 */
final class FakeBcryptClaimer implements LegacyPasswordVerifier
{
    public function canHandle(string $encodedHash): bool
    {
        return str_starts_with($encodedHash, '$2b$');
    }

    public function verify(#[\SensitiveParameter] string $password, string $encodedHash): bool
    {
        return false;
    }
}
