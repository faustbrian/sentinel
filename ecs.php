<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\CodingStandard\EasyCodingStandard\Factory;
use Cline\CodingStandard\PhpCsFixer\Fixer\ImportFqcnInStaticCallFixer;
use PhpCsFixer\Fixer\ClassNotation\FinalClassFixer;
use PhpCsFixer\Fixer\ClassNotation\SelfAccessorFixer;
use Symplify\EasyCodingStandard\Config\ECSConfig;

return static function (ECSConfig $config): void {
    Factory::create(
        paths: [__DIR__.'/src', __DIR__.'/tests'],
    )($config);

    $config->skip([
        FinalClassFixer::class => [
            __DIR__.'/src/Exceptions/SentinelException.php',
        ],
        SelfAccessorFixer::class => [
            __DIR__.'/src/Facades/Sentinel.php',
        ],
        ImportFqcnInStaticCallFixer::class => [
            __DIR__.'/src/Facades/Sentinel.php',
        ],
    ]);
};
