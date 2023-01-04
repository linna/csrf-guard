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
use Linna\CsrfGuard\Provider\EncryptionTokenProvider;
use PHPUnit\Framework\TestCase;

//use TypeError;

/**
 * Cross-site Request Forgery Guard
 * Encryption Token Provider Test
 */
class EncryptionTokenProviderTest extends TestCase
{
    /**
     * Test new instance.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testNewInstance(): void
    {
        \session_start();

        //only session id
        $this->assertInstanceOf(EncryptionTokenProvider::class, (new EncryptionTokenProvider()));
        //session id and expire time
        $this->assertInstanceOf(EncryptionTokenProvider::class, (new EncryptionTokenProvider(expire: 300)));
        //session id, expire time and storage size
        $this->assertInstanceOf(EncryptionTokenProvider::class, (new EncryptionTokenProvider(expire: 300, storageSize: 32)));

        \session_destroy();
    }

    /**
     * Test method get token.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testGetToken(): void
    {
        \session_start();

        $provider = new EncryptionTokenProvider();

        $token = $provider->getToken();

        $this->assertGreaterThan(0, \strlen($token));
        $this->assertSame(\strlen($token), 176);

        \session_destroy();
    }

    /**
     * Test method validate.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testValidateValidToken(): void
    {
        \session_start();

        $provider = new EncryptionTokenProvider();

        $this->assertTrue($provider->validate($provider->getToken()));

        \session_destroy();
    }

    /**
     * Test method validate using invalid token.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testValidateInvalidToken(): void
    {
        \session_start();

        $provider = new EncryptionTokenProvider();
        //$token = $provider->getToken();

        //generate a random token
        $randomToken = \bin2hex(\random_bytes(88));
        //byte flipped token
        $offset = \random_int(0, 87);
        $token = $provider->getToken();
        $byteFlippedToken = \substr($token, $offset, 1) === 'a' ?
                \substr_replace($token, 'b', $offset, 1) :
                \substr_replace($token, 'a', $offset, 1);

        $this->assertFalse($provider->validate($randomToken));
        $this->assertFalse($provider->validate($byteFlippedToken));

        \session_destroy();
    }

    /**
     * Test verify session storage.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testVerifySessionStorage(): void
    {
        \session_start();

        $provider = new EncryptionTokenProvider(storageSize: 16);

        for ($i = 1; $i < 20; $i++) {
            $this->assertTrue($provider->validate($provider->getToken()));

            if ($i > 16) {
                $this->assertSame(16, \count($_SESSION['csrf_encryption_nonce']));
                continue;
            }

            $this->assertSame($i, \count($_SESSION['csrf_encryption_nonce']));
        }

        \session_destroy();
    }

    /**
     * Test verify session storage overflow.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testVerifySessionStorageOverflow(): void
    {
        \session_start();

        $provider = new EncryptionTokenProvider(storageSize: 5);

        //genetate a token and validate immediately
        $token0 = $provider->getToken();
        $this->assertTrue($provider->validate($token0));

        $token1 = $provider->getToken();
        $this->assertTrue($provider->validate($token1));

        $token2 = $provider->getToken();
        $this->assertTrue($provider->validate($token2));

        $token3 = $provider->getToken();
        $this->assertTrue($provider->validate($token3));

        $token4 = $provider->getToken();
        $this->assertTrue($provider->validate($token4));

        $token5 = $provider->getToken();
        $this->assertTrue($provider->validate($token5));

        $token6 = $provider->getToken();
        $this->assertTrue($provider->validate($token6));

        $token7 = $provider->getToken();
        $this->assertTrue($provider->validate($token7));

        //revalidate, only last 5 tokens are valid
        //nonce storage excedeed
        $this->assertFalse($provider->validate($token0));
        $this->assertFalse($provider->validate($token1));
        $this->assertFalse($provider->validate($token2));
        $this->assertTrue($provider->validate($token3));
        $this->assertTrue($provider->validate($token4));
        $this->assertTrue($provider->validate($token5));
        $this->assertTrue($provider->validate($token6));
        $this->assertTrue($provider->validate($token7));

        \session_destroy();
    }

    /**
     * Test verify same token over same session.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testVerifyTokenOverSameSessions(): void
    {
        \session_start();

        $provider = new EncryptionTokenProvider(storageSize: 5);

        //genetate a token
        $token = $provider->getToken();
        $this->assertTrue($provider->validate($token));

        \session_write_close();

        // restart the session
        \session_start();

        $providerRestartedSession = new EncryptionTokenProvider(storageSize: 5);
        $this->assertTrue($providerRestartedSession->validate($token));

        \session_destroy();
    }

    /**
     * Test verify same token over different session.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testVerifyTokenOverDifferentSessions(): void
    {
        \session_start();

        $provider = new EncryptionTokenProvider(storageSize: 5);

        //genetate a token
        $token = $provider->getToken();
        $this->assertTrue($provider->validate($token));

        \session_destroy();

        // start the new session
        \session_start();

        $providerNewSession = new EncryptionTokenProvider(storageSize: 5);
        $this->assertFalse($providerNewSession->validate($token));

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

        (new EncryptionTokenProvider(expire: $expire));
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

        (new EncryptionTokenProvider(storageSize: $storageSize));
    }
}
