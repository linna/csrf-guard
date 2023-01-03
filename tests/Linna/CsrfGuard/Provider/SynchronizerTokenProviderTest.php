<?php

declare(strict_types=1);

/**
 * This file is part of the Linna Csrf Guard.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */

namespace Linna\CsrfGuard\Provider;

use Linna\CsrfGuard\Exception\BadExpireException;
use Linna\CsrfGuard\Exception\BadStorageSizeException;
use Linna\CsrfGuard\Exception\BadTokenLengthException;
use Linna\CsrfGuard\Provider\SynchronizerTokenProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cross-site Request Forgery Guard
 * Synchronizer Token Provider Test
 */
class SynchronizerTokenProviderTest extends TestCase
{
    /**
     * Test new instance.
     *
     * @runInSeparateProcess
     */
    public function testNewInstance(): void
    {
        \session_start();

        //only session id
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider()));
        //session id and expire time
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(300)));
        //session id, expire time and storage size
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(300, 32)));
        //session id, expire time, storage size and token length
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(300, 32, 16)));

        \session_destroy();
    }

    /**
     * Bad expire provider.
     * Provide expire time values out of range.
     *
     * @return array<array>
     */
    public function badExpireProvider(): array
    {
        return [
            [-1],
            [86401]
        ];
    }

    /**
     * Test new instance with wrong arguments for expire time.
     *
     * @dataProvider badExpireProvider
     *
     * @param int $expire
     *
     * @return void
     */
    public function testNewInstanceWithBadExpire($expire): void
    {
        $this->expectException(BadExpireException::class);
        $this->expectExceptionMessage('Expire time must be between 0 and 86400');

        (new SynchronizerTokenProvider($expire));
    }

    /**
     * Bad storage size provider.
     * Provide storage size values out of range.
     *
     * @return array<array>
     */
    public function badStorageSizeProvider(): array
    {
        return [
            [1],
            [65]
        ];
    }

    /**
     * Test new instance with wrong arguments for storage size.
     *
     * @dataProvider badStorageSizeProvider
     *
     * @param int $storageSize
     *
     * @return void
     */
    public function testNewInstanceWithBadStorageSize($storageSize): void
    {
        $this->expectException(BadStorageSizeException::class);
        $this->expectExceptionMessage('Storage size must be between 2 and 64');

        (new SynchronizerTokenProvider(300, $storageSize));
    }

    /**
     * Bad token length provider.
     * Provide token length values out of range.
     *
     * @return array<array>
     */
    public function badTokenLengthProvider(): array
    {
        return [
            [15],
            [129]
        ];
    }

    /**
     * Test new instance with wrong arguments for token length.
     *
     * @dataProvider badTokenLengthProvider
     *
     * @param int $tokenLength
     *
     * @return void
     */
    public function testNewInstanceWithBadTokenLength($tokenLength): void
    {
        $this->expectException(BadTokenLengthException::class);
        $this->expectExceptionMessage('Token length must be between 16 and 128');

        (new SynchronizerTokenProvider(300, 16, $tokenLength));
    }
}
