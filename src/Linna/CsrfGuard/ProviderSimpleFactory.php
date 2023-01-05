<?php

declare(strict_types=1);

/**
 * This file is part of the Linna Csrf Guard.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */

namespace Linna\CsrfGuard;

use Linna\CsrfGuard\Provider\EncryptionTokenProvider;
use Linna\CsrfGuard\Provider\HmacTokenProvider;
use Linna\CsrfGuard\Provider\SynchronizerTokenProvider;
use Linna\CsrfGuard\Provider\TokenProviderInterface;

use InvalidArgumentException;
use RuntimeException;
use ReflectionClass;

/**
 * Csrf toke provider factory.
 */
class ProviderSimpleFactory
{
    /** @var array<string> List of classes that implement TokeProviderInterface. */
    private static array $providers = [
        EncryptionTokenProvider::class,
        HmacTokenProvider::class,
        SynchronizerTokenProvider::class
    ];

    /**
     * Create a Csrf token provider.
     *
     * @param class-string              $provider The token provider for which we need an instance.
     * @param array<string, int|string> $options  Specific options for the token provider.
     *
     * @return TokenProviderInterface The token provider instance.
     *
     * @throws InvalidArgumentException If the passed provider isn't a valid token provider.
     * @throws RuntimeException         If the creation of the token provider instance fails.
     */
    public static function getProvider(string $provider = SynchronizerTokenProvider::class, array $options = []): TokenProviderInterface
    {
        if (!\in_array($provider, self::$providers)) {
            throw new InvalidArgumentException("{$provider} is not a valid provider");
        }

        $providerInstance =  (new ReflectionClass($provider))->newInstanceArgs($options);

        if (!($providerInstance instanceof TokenProviderInterface)) {
            throw new RuntimeException('Unable to create provider');
        }

        return $providerInstance;
    }
}
