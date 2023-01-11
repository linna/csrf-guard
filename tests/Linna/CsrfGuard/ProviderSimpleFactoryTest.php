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

use ArrayObject;
use InvalidArgumentException;
use Linna\CsrfGuard\ProviderSimpleFactory;
use Linna\CsrfGuard\Provider\EncryptionTokenProvider;
use Linna\CsrfGuard\Provider\HmacTokenProvider;
use Linna\CsrfGuard\Provider\SynchronizerTokenProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cross-site Request Forgery Guard.
 * Provider Simple Factory Test.
 */
class ProviderSimpleFactoryTest extends TestCase
{
    /**
     * Test new instanse using default values.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testNewInstance(): void
    {
        \session_start();

        $provider = ProviderSimpleFactory::getProvider();

        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        \session_destroy();
    }

    /**
     * Test new instanse passing parameters.
     *
     * @runInSeparateProcess
     *
     * @return void
     *
     */
    public function testNewInstanceWithArguments(): void
    {
        \session_start();

        $provider = ProviderSimpleFactory::getProvider(SynchronizerTokenProvider::class, options: ["tokenLength" => 17]);

        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);
        $this->assertSame(34, \strlen($provider->getToken()));

        \session_destroy();
    }

    /**
     * Class provider.
     *
     * @return array<array>
     */
    public function classProvider(): array
    {
        return [
            [EncryptionTokenProvider::class, []],
            [HmacTokenProvider::class, ["value" => 'the value will be hashed', "key" => 'authentication key']],
            [SynchronizerTokenProvider::class, []]
        ];
    }

    /**
     * Test all supported providers.
     *
     * @dataProvider classProvider
     *
     * @runInSeparateProcess
     *
     * @param string $class
     */
    public function testAllProviders(string $class, array $args)
    {
        \session_start();

        $provider = ProviderSimpleFactory::getProvider($class, $args);

        $this->assertInstanceOf($class, $provider);
        $this->assertTrue($provider->validate($provider->getToken()));

        \session_destroy();
    }

    /**
     * Test get provider with invalid provider.
     *
     * @return void
     */
    public function testGetProviderWithInvalidProvider(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ArrayObject is not a valid provider');

        $provider = ProviderSimpleFactory::getProvider(ArrayObject::class);
    }
}
