<?php

declare(strict_types=1);

// 測試 bootstrap：ARGONGUARD_TESTING 常數是 sodium-provider 強制切換的雙重門檻之一
// （見 src/Engine/Argon2Providers.php）。此常數只在測試進程定義，生產部署不存在，
// 故即使生產環境誤設 ARGONGUARD_TEST_FORCE_PROVIDER 也不會切換 provider。
define('ARGONGUARD_TESTING', true);

require __DIR__ . '/../vendor/autoload.php';
