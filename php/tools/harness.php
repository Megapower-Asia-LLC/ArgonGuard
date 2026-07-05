<?php

declare(strict_types=1);

/**
 * ArgonGuard dev harness（協議凍結於 spec/harness-contract.json，schemaVersion 1；baseline §6）。
 * stdin 單一 JSON：{"schemaVersion":1,"commands":[…]} → stdout 單行 JSON：{"schemaVersion":1,"results":[…]}
 * op：hash{profile,passwordHex}／verify{passwordHex,encoded}／needsRehash{activeProfile,encoded,legacyRegistered?}
 * passwordHex → 位元組直接作為 PHP 密碼字串（PHP string 即 bytes）。
 *
 * 啟動：php /Users/aikenlin/Projects/_Megapower/ArgonGuard/php/tools/harness.php（見 php/HARNESS_CMD）
 */

// 自帶 PSR-4 autoloader：零 runtime Composer 依賴（vendor/ 僅供 dev 測試）。
spl_autoload_register(static function (string $class): void {
    $prefix = 'ArgonGuard\\Passwords\\';
    if (str_starts_with($class, $prefix)) {
        $path = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    }
});

use ArgonGuard\Passwords\ArgonGuardException;
use ArgonGuard\Passwords\ArgonGuardPasswordHasher;
use ArgonGuard\Passwords\ArgonGuardProfile;
use ArgonGuard\Passwords\Legacy\LegacyPasswordVerifier;

/** harness 協議中 legacyRegistered=true 的標準認領器（與向量語意一致；baseline §6）。 */
final class BcryptPrefixClaimer implements LegacyPasswordVerifier
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

function parseProfile(string $name): ArgonGuardProfile
{
    return match ($name) {
        'default' => ArgonGuardProfile::Default,
        'high' => ArgonGuardProfile::High,
        'highest' => ArgonGuardProfile::Highest,
        default => throw new UnexpectedValueException("unknown profile: {$name}"),
    };
}

$input = json_decode((string) stream_get_contents(STDIN), true, 64, JSON_THROW_ON_ERROR);
if (($input['schemaVersion'] ?? null) !== 1) {
    fwrite(STDERR, "unsupported schemaVersion\n");
    exit(2);
}

$results = [];
foreach ($input['commands'] as $cmd) {
    try {
        switch ($cmd['op'] ?? null) {
            case 'hash':
                $hasher = new ArgonGuardPasswordHasher(parseProfile($cmd['profile']));
                $results[] = ['ok' => true, 'encoded' => $hasher->hashPassword((string) hex2bin($cmd['passwordHex']))];
                break;
            case 'verify':
                $hasher = new ArgonGuardPasswordHasher();
                $results[] = [
                    'ok' => true,
                    'value' => $hasher->verifyPassword((string) hex2bin($cmd['passwordHex']), $cmd['encoded']),
                ];
                break;
            case 'needsRehash':
                $legacy = ($cmd['legacyRegistered'] ?? false) ? [new BcryptPrefixClaimer()] : [];
                $hasher = new ArgonGuardPasswordHasher(parseProfile($cmd['activeProfile']), $legacy);
                $results[] = ['ok' => true, 'value' => $hasher->needsRehash($cmd['encoded'])];
                break;
            default:
                $results[] = ['ok' => false, 'error' => 'HarnessError', 'reason' => 'unknown_op'];
                break;
        }
    } catch (ArgonGuardException $e) {
        $shortName = substr($e::class, (int) strrpos($e::class, '\\') + 1);
        $results[] = [
            'ok' => false,
            'error' => str_replace('Exception', '', $shortName), // 五類別名，無 "Exception" 後綴
            'reason' => $e->getReason(),
        ];
    }
}

echo json_encode(['schemaVersion' => 1, 'results' => $results], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
