<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\MalformedHashException;
use ArgonGuard\Passwords\Phc\PhcParser;
use ArgonGuard\Passwords\ReasonCodes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** 嚴格 PHC parser 合法／非法路徑（SPEC §4 S1–S4；baseline §4 文法澄清）。 */
final class PhcParserTest extends TestCase
{
    private const VALID = '$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE';

    // ─── tryGetAlgorithm（dispatch 前置 token 判斷；baseline §1）───

    /** @return iterable<string, array{string, ?string}> */
    public static function algorithmTokenCases(): iterable
    {
        yield 'argon2id' => [self::VALID, 'argon2id'];
        yield 'argon2i' => ['$argon2i$v=19$m=1,t=1,p=1$aaaa$bbbb', 'argon2i'];
        yield 'bcrypt-2b' => ['$2b$12$abcdefghijk', '2b'];
        yield 'dash-token' => ['$scrypt-x$rest', 'scrypt-x'];
        yield 'garbage' => ['not-a-hash-at-all', null];
        yield 'empty' => ['', null];
        yield 'lone-dollar' => ['$', null];
        yield 'empty-token' => ['$$rest', null];
        yield 'no-second-dollar' => ['$argon2id', null];
        yield 'uppercase-token' => ['$Argon2ID$rest', null];
        yield 'token-with-space' => ['$argon 2$rest', null];
        yield 'token-with-underscore' => ['$argon_2$rest', null];
    }

    #[DataProvider('algorithmTokenCases')]
    public function testTryGetAlgorithm(string $encoded, ?string $expected): void
    {
        self::assertSame($expected, PhcParser::tryGetAlgorithm($encoded));
    }

    // ─── 合法路徑 ───

    public function testParseValidString(): void
    {
        $h = PhcParser::parse(self::VALID);
        self::assertSame('argon2id', $h->algorithm);
        self::assertSame(19, $h->version);
        self::assertSame(19456, $h->m);
        self::assertSame(2, $h->t);
        self::assertSame(1, $h->p);
        self::assertSame(16, strlen($h->salt));
        self::assertSame(32, strlen($h->tag));
        self::assertFalse($h->hasKeyid);
        self::assertFalse($h->hasData);
    }

    public function testParseMissingVersionIsParseableVersionNull(): void
    {
        // 缺 v 是可解析的；由政策層裁決 missing_version（SPEC F2）
        $h = PhcParser::parse('$argon2id$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE');
        self::assertNull($h->version);
    }

    public function testParseKeyidDataFlagsSurfaceToPolicy(): void
    {
        $h = PhcParser::parse('$argon2id$v=19$m=19456,t=2,p=1,keyid=Zm9v$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE');
        self::assertTrue($h->hasKeyid);
        $h = PhcParser::parse('$argon2id$v=19$m=19456,t=2,p=1,data=Zm9v$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE');
        self::assertTrue($h->hasData);
    }

    public function testParseZeroValueAllowedByGrammar(): void
    {
        // 單獨 "0" 合法（政策層才拒絕）；文法只禁前導零
        $h = PhcParser::parse('$argon2id$v=19$m=0,t=0,p=0$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE');
        self::assertSame(0, $h->m);
    }

    public function testEncodeRoundTrip(): void
    {
        $h = PhcParser::parse(self::VALID);
        self::assertSame(self::VALID, PhcParser::encode($h->m, $h->t, $h->p, $h->salt, $h->tag));
    }

    // ─── 非法路徑（reason 精確比對）───

    /** @return iterable<string, array{string, string}> */
    public static function malformedCases(): iterable
    {
        $salt = 'QXJvbkd1YXJkVjFTMDEhIQ';
        $tag = 'IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE';

        // not_phc：整體結構
        yield 'empty' => ['', ReasonCodes::NOT_PHC];
        yield 'no-leading-dollar' => ["argon2id\$v=19\$m=19456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'four-segments' => ['$argon2id$v=19$m=19456,t=2,p=1', ReasonCodes::NOT_PHC];
        yield 'seven-segments' => ["\$argon2id\$v=19\$m=19456,t=2,p=1\${$salt}\${$tag}\$extra", ReasonCodes::NOT_PHC];
        yield 'empty-algorithm' => ["\$\$v=19\$m=19456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'uppercase-algorithm' => ["\$Argon2id\$v=19\$m=19456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'v-not-third-segment' => ["\$argon2id\$m=19456,t=2,p=1\$v=19\${$salt}\${$tag}", ReasonCodes::NOT_PHC];

        // not_phc：數字文法（baseline §4）
        yield 'leading-zero-m' => ["\$argon2id\$v=19\$m=019456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'sixteen-digit-m' => ["\$argon2id\$v=19\$m=1234567890123456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'signed-m' => ["\$argon2id\$v=19\$m=+19456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'negative-t' => ["\$argon2id\$v=19\$m=19456,t=-2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'empty-m' => ["\$argon2id\$v=19\$m=,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'hex-m' => ["\$argon2id\$v=19\$m=0x4c00,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'leading-zero-v' => ["\$argon2id\$v=019\$m=19456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'non-numeric-v' => ["\$argon2id\$v=abc\$m=19456,t=2,p=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];

        // not_phc：params 段第 4 個起僅允許 keyid=/data=
        yield 'unknown-fourth-param' => ["\$argon2id\$v=19\$m=19456,t=2,p=1,x=1\${$salt}\${$tag}", ReasonCodes::NOT_PHC];
        yield 'two-params-only' => ["\$argon2id\$v=19\$m=19456,t=2\${$salt}\${$tag}", ReasonCodes::NOT_PHC];

        // params_out_of_order：前三 token 是 m/t/p 的重排
        yield 't-before-m' => ["\$argon2id\$v=19\$t=2,m=19456,p=1\${$salt}\${$tag}", ReasonCodes::PARAMS_OUT_OF_ORDER];
        yield 'p-m-t' => ["\$argon2id\$v=19\$p=1,m=19456,t=2\${$salt}\${$tag}", ReasonCodes::PARAMS_OUT_OF_ORDER];
        yield 'm-p-t' => ["\$argon2id\$v=19\$m=19456,p=1,t=2\${$salt}\${$tag}", ReasonCodes::PARAMS_OUT_OF_ORDER];

        // bad_base64
        yield 'padded-salt' => ["\$argon2id\$v=19\$m=19456,t=2,p=1\${$salt}==\$ERERERERERERERERERERERERERERERERERERERERERE", ReasonCodes::BAD_BASE64];
        yield 'base64url-tag' => ["\$argon2id\$v=19\$m=19456,t=2,p=1\${$salt}\$-_ERERERERERERERERERERERERERERERERERERERERE", ReasonCodes::BAD_BASE64];
        yield 'empty-salt' => ["\$argon2id\$v=19\$m=19456,t=2,p=1\$\${$tag}", ReasonCodes::BAD_BASE64];
        yield 'len-mod4-eq-1-salt' => ["\$argon2id\$v=19\$m=19456,t=2,p=1\$QXJvb\${$tag}", ReasonCodes::BAD_BASE64];
        yield 'non-canonical-trailing-bits' => ["\$argon2id\$v=19\$m=19456,t=2,p=1\$QXJvbkd1YXJkVjFTMDEhIR\${$tag}", ReasonCodes::BAD_BASE64];
        yield 'whitespace-in-salt' => ["\$argon2id\$v=19\$m=19456,t=2,p=1\$QXJvbkd1 YXJkVjFTMDEhIQ\${$tag}", ReasonCodes::BAD_BASE64];
    }

    #[DataProvider('malformedCases')]
    public function testParseRejectsMalformed(string $encoded, string $expectedReason): void
    {
        try {
            PhcParser::parse($encoded);
            self::fail('expected MalformedHashException');
        } catch (MalformedHashException $ex) {
            self::assertSame($expectedReason, $ex->getReason());
        }
    }

    public function testEncodeEmitsExplicitVersionAndOrderedParams(): void
    {
        $salt = VectorData::hex('41726f6e477561726456315330312121');
        $encoded = PhcParser::encode(19456, 2, 1, $salt, str_repeat("\x11", 32));
        self::assertStringStartsWith('$argon2id$v=19$m=19456,t=2,p=1$', $encoded); // G1–G3
        self::assertStringNotContainsString('=', substr($encoded, strlen('$argon2id$v=19$m=19456,t=2,p=1$'))); // G5 無 padding
    }
}
