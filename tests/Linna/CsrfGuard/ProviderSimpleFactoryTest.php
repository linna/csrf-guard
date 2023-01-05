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

use Linna\CsrfGuard\ProviderSimpleFactory;
use Linna\CsrfGuard\Exception\BadExpireException;
use Linna\CsrfGuard\Exception\BadStorageSizeException;
use Linna\CsrfGuard\Exception\SessionNotStartedException;
use Linna\CsrfGuard\Provider\EncryptionTokenProvider;
use Linna\CsrfGuard\Provider\HmacTokenProvider;
use Linna\CsrfGuard\Provider\SynchronizerTokenProvider;
use PHPUnit\Framework\TestCase;

//use TypeError;

/**
 * Cross-site Request Forgery Guard.
 * Provider Simple Factory Test.
 */
class ProviderSimpleFactoryTest extends TestCase
{
    /**
     * Test ger default provider.
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
}
