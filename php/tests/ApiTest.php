<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\ArgonGuardPasswordHasher;
use ArgonGuard\Passwords\ArgonGuardProfile;
use ArgonGuard\Passwords\InvalidInputException;
use ArgonGuard\Passwords\Legacy\LegacyPasswordVerifier;
use ArgonGuard\Passwords\MalformedHashException;
use ArgonGuard\Passwords\Phc\PhcParser;
use ArgonGuard\Passwords\ProfileParameters;
use ArgonGuard\Passwords\ReasonCodes;
use ArgonGuard\Passwords\SpecVersion;
use ArgonGuard\Passwords\UnsupportedAlgorithmException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** 公開 API 行為（SPEC §2、§3、§5、§6）。 */
final class ApiTest extends TestCase
{
    public function testSpecVersionIsFrozen(): void
    {
        self::assertSame('1.0.0', SpecVersion::VALUE);
    }

    /** P1 永久哨兵：default 檔位必須恆等於 (m=19456, t=2, p=1)。 */
    public function testDefaultProfileSentinel(): void
    {
        $p = ProfileParameters::forProfile(ArgonGuardProfile::Default);
        self::assertSame([19456, 2, 1, 16, 32], [$p->m, $p->t, $p->p, $p->saltBytes, $p->tagBytes]);
    }

    /** @return iterable<string, array{ArgonGuardProfile, string}> */
    public static function profiles(): iterable
    {
        yield 'default' => [ArgonGuardProfile::Default, '$argon2id$v=19$m=19456,t=2,p=1$'];
        yield 'high' => [ArgonGuardProfile::High, '$argon2id$v=19$m=65536,t=2,p=1$'];
        yield 'highest' => [ArgonGuardProfile::Highest, '$argon2id$v=19$m=131072,t=2,p=1$'];
    }

    #[DataProvider('profiles')]
    public function testHashFormatAndRoundTrip(ArgonGuardProfile $profile, string $expectedPrefix): void
    {
        $hasher = new ArgonGuardPasswordHasher($profile);
        $encoded = $hasher->hashPassword('correct horse battery staple');

        self::assertStringStartsWith($expectedPrefix, $encoded); // G1–G3、G8
        self::assertGreaterThanOrEqual(97, strlen($encoded));    // G9
        self::assertLessThanOrEqual(98, strlen($encoded));

        $parsed = PhcParser::parse($encoded); // 嚴格文法可解析（G5 no padding、canonical）
        self::assertSame(16, strlen($parsed->salt)); // G6
        self::assertSame(32, strlen($parsed->tag));  // G7

        self::assertTrue($hasher->verifyPassword('correct horse battery staple', $encoded));
        self::assertFalse($hasher->verifyPassword('wrong password', $encoded)); // V1：false＝密碼不符
        self::assertFalse($hasher->needsRehash($encoded));
    }

    /** G6：salt 每次雜湊新產生（CSPRNG）→ 相同密碼兩次輸出必不同。 */
    public function testFreshSaltPerHash(): void
    {
        $hasher = new ArgonGuardPasswordHasher();
        self::assertNotSame($hasher->hashPassword('password'), $hasher->hashPassword('password'));
    }

    /** needsRehash 對非 active 檔位（含更強）恆 true；不做任何雜湊。 */
    public function testNeedsRehashConvergesToActiveProfile(): void
    {
        $default = new ArgonGuardPasswordHasher(ArgonGuardProfile::Default);
        $strongerEncoded = VectorData::entry('deterministic.json', 'det-ascii-high')['encoded'];
        self::assertTrue($default->needsRehash($strongerEncoded));
    }

    // ─── 輸入規則（SPEC §5；baseline §2 優先序）───

    /** @return iterable<string, array{string, string}> */
    public static function invalidPasswords(): iterable
    {
        yield 'empty' => ['', ReasonCodes::PASSWORD_EMPTY];
        yield 'too-long-1025' => [str_repeat('a', 1025), ReasonCodes::PASSWORD_TOO_LONG];
        yield 'nul' => ["pass\0word", ReasonCodes::PASSWORD_CONTAINS_NUL];
        // 優先序：too_long 先於 contains_nul（baseline §2）
        yield 'too-long-and-nul' => ["\0" . str_repeat('a', 1025), ReasonCodes::PASSWORD_TOO_LONG];
    }

    #[DataProvider('invalidPasswords')]
    public function testHashAndVerifyApplyIdenticalInputRules(string $password, string $expectedReason): void
    {
        $hasher = new ArgonGuardPasswordHasher();
        $encoded = VectorData::entry('deterministic.json', 'det-ascii-default')['encoded'];

        try {
            $hasher->hashPassword($password);
            self::fail('hashPassword should reject');
        } catch (InvalidInputException $ex) {
            self::assertSame($expectedReason, $ex->getReason());
        }

        try {
            $hasher->verifyPassword($password, $encoded);
            self::fail('verifyPassword should reject');
        } catch (InvalidInputException $ex) {
            self::assertSame($expectedReason, $ex->getReason());
        }
    }

    /** 1024 bytes 上限含邊界；PHP string 即 bytes（strlen 計）。 */
    public function testMaxLengthBoundaryAccepted(): void
    {
        $hasher = new ArgonGuardPasswordHasher();
        $encoded = $hasher->hashPassword(str_repeat('a', 1024));
        self::assertTrue($hasher->verifyPassword(str_repeat('a', 1024), $encoded));
    }

    // ─── Legacy 擴充點（SPEC §6.4）───

    /** 第一個認領者裁決（SPEC §6.2）。 */
    public function testFirstClaimerDecides(): void
    {
        $first = new RecordingVerifier(prefix: '$2b$', result: true);
        $second = new RecordingVerifier(prefix: '$2b$', result: false);
        $hasher = new ArgonGuardPasswordHasher(ArgonGuardProfile::Default, [$first, $second]);

        self::assertTrue($hasher->verifyPassword('password', '$2b$12$LQVkVYq1S7Ck1MQIViYyNOG3Fabe/y0BB6kJ1O8ZQNXY9nCzC1jU6'));
        self::assertSame(1, $first->verifyCalls);
        self::assertSame(0, $second->verifyCalls);
    }

    /** out-of-policy argon2id（p=2）只能由顯式註冊的 legacy verifier 認領（V2）。 */
    public function testOutOfPolicyArgon2idClaimableByLegacy(): void
    {
        $claimer = new RecordingVerifier(prefix: '$argon2id$', result: true);
        $hasher = new ArgonGuardPasswordHasher(ArgonGuardProfile::Default, [$claimer]);
        $p2 = VectorData::entry('reject.json', 'rej-p2')['encoded'];

        self::assertTrue($hasher->verifyPassword('password', $p2));
        self::assertSame(1, $claimer->verifyCalls);
    }

    /** malformed argon2id（bad base64）無人認領 → 原 reason 的 MalformedHash。 */
    public function testMalformedArgon2idKeepsSpecificReasonWhenUnclaimed(): void
    {
        $claimer = new RecordingVerifier(prefix: '$2b$', result: true); // 不認領 argon2id
        $hasher = new ArgonGuardPasswordHasher(ArgonGuardProfile::Default, [$claimer]);
        $bad = VectorData::entry('reject.json', 'rej-b64-padding')['encoded'];

        try {
            $hasher->verifyPassword('password', $bad);
            self::fail('expected MalformedHashException');
        } catch (MalformedHashException $ex) {
            self::assertSame(ReasonCodes::BAD_BASE64, $ex->getReason());
        }
    }

    /** L1：清單建構時複製；建構後修改來源陣列不得影響 hasher。 */
    public function testLegacyVerifierListImmutableAfterConstruction(): void
    {
        $verifiers = [new RecordingVerifier(prefix: '$2b$', result: true)];
        $hasher = new ArgonGuardPasswordHasher(ArgonGuardProfile::Default, $verifiers);

        $verifiers[] = new RecordingVerifier(prefix: '$argon2i$', result: true); // 事後加入不生效
        array_shift($verifiers);

        self::assertTrue($hasher->verifyPassword('password', '$2b$12$LQVkVYq1S7Ck1MQIViYyNOG3Fabe/y0BB6kJ1O8ZQNXY9nCzC1jU6'));
        $argon2i = VectorData::entry('reject.json', 'rej-argon2i')['encoded'];
        try {
            $hasher->verifyPassword('password', $argon2i);
            self::fail('expected UnsupportedAlgorithmException');
        } catch (UnsupportedAlgorithmException $ex) {
            self::assertSame(ReasonCodes::UNSUPPORTED_ALGORITHM, $ex->getReason());
        }
    }

    public function testConstructorRejectsNonVerifierItems(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        /** @phpstan-ignore-next-line 故意傳入錯誤型別 */
        new ArgonGuardPasswordHasher(ArgonGuardProfile::Default, ['not-a-verifier']);
    }

    /** needsRehash 的長度預檢（>512 → encoded_too_long）。 */
    public function testNeedsRehashLengthPrecheck(): void
    {
        $hasher = new ArgonGuardPasswordHasher();
        try {
            $hasher->needsRehash('$argon2id$' . str_repeat('a', 512));
            self::fail('expected MalformedHashException');
        } catch (MalformedHashException $ex) {
            self::assertSame(ReasonCodes::ENCODED_TOO_LONG, $ex->getReason());
        }
    }
}

/** 記錄呼叫次數的測試用 legacy verifier。 */
final class RecordingVerifier implements LegacyPasswordVerifier
{
    public int $verifyCalls = 0;

    public function __construct(private readonly string $prefix, private readonly bool $result)
    {
    }

    public function canHandle(string $encodedHash): bool
    {
        return str_starts_with($encodedHash, $this->prefix);
    }

    public function verify(#[\SensitiveParameter] string $password, string $encodedHash): bool
    {
        $this->verifyCalls++;

        return $this->result;
    }
}
