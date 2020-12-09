<?php

/**
 * Linna Cross-site Request Forgery Guard
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Tests\Provider;

use Linna\CsrfGuard\Exception\BadExpireException;
use Linna\CsrfGuard\Exception\BadStorageSizeException;
use Linna\CsrfGuard\Exception\BadTokenLenghtException;
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
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(\session_id())));
        //session id and expire time
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(\session_id(), 300)));
        //session id, expire time and storage size
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(\session_id(), 300, 32)));
        //session id, expire time, storage size and token lenght
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(\session_id(), 300, 32, 16)));

        \session_destroy();
    }

    /**
     * Bad expire provider.
     * Provide expire time values out of range.
     *
     * @return array
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

        (new SynchronizerTokenProvider('a_random_session_id', $expire));
    }

    /**
     * Bad storage size provider.
     * Provide storage size values out of range.
     *
     * @return array
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

        (new SynchronizerTokenProvider('a_random_session_id', 300, $storageSize));
    }

    /**
     * Bad token lenght provider.
     * Provide token lenght values out of range.
     *
     * @return array
     */
    public function badTokenLenghtProvider(): array
    {
        return [
            [15],
            [129]
        ];
    }

    /**
     * Test new instance with wrong arguments for token lenght.
     *
     * @dataProvider badTokenLenghtProvider
     *
     * @param int $tokenLenght
     *
     * @return void
     */
    public function testNewInstanceWithBadTokenLenght($tokenLenght): void
    {
        $this->expectException(BadTokenLenghtException::class);
        $this->expectExceptionMessage('Token lenght must be between 16 and 128');

        (new SynchronizerTokenProvider('a_random_session_id', 300, 16, $tokenLenght));
    }
}
