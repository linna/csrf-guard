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
use Linna\CsrfGuard\Exception\SessionNotStartedException;
use Linna\CsrfGuard\Provider\SynchronizerTokenProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cross-site Request Forgery Guard.
 * Synchronizer Token Provider Test.
 */
class SynchronizerTokenProviderTest extends TestCase
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
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider()));
        //session id and expire time
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(expire: 300)));
        //session id, expire time and storage size
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(expire: 300, storageSize: 32)));
        //session id, expire time, storage size and token length
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(expire: 300, storageSize: 32, tokenLength: 16)));

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

        $provider = new SynchronizerTokenProvider();
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        $token = $provider->getToken();

        $this->assertGreaterThan(0, \strlen($token));
        $this->assertSame(64, \strlen($token));

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

        $provider = new SynchronizerTokenProvider();
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

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

        $provider = new SynchronizerTokenProvider();
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        //generate a random token
        $randomToken = \bin2hex(\random_bytes(64));

        $this->assertFalse($provider->validate($randomToken));

        \session_destroy();
    }

    /**
     * Test verify session started.
     *
     * @return void
     */
    public function testVerifySessionStarted(): void
    {
        $this->expectException(SessionNotStartedException::class);
        $this->expectExceptionMessage('Session not started, enable it and start one before use this token provider');

        (new SynchronizerTokenProvider());
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

        $provider = new SynchronizerTokenProvider(storageSize: 16);
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        for ($i = 1; $i < 20; $i++) {
            $this->assertTrue($provider->validate($provider->getToken()));

            if ($i > 16) {
                $this->assertSame(16, \count($_SESSION['csrf_syncronizer_token']));
                continue;
            }

            $this->assertSame($i, \count($_SESSION['csrf_syncronizer_token']));
        }

        \session_destroy();
    }

    /**
     * Test verify session default storage.
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testVerifySessionDefaultStorage(): void
    {
        \session_start();

        $provider = new SynchronizerTokenProvider();
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        //genetate a token
        $token0 = $provider->getToken();
        $token1 = $provider->getToken();
        $token2 = $provider->getToken();
        $token3 = $provider->getToken();
        $token4 = $provider->getToken();
        $token5 = $provider->getToken();
        $token6 = $provider->getToken();
        $token7 = $provider->getToken();
        $token8 = $provider->getToken();
        $token9 = $provider->getToken();
        $token10 = $provider->getToken();
        $token11 = $provider->getToken();
        $token12 = $provider->getToken();
        $token13 = $provider->getToken();

        //revalidate, only 10 tokens are valid
        //nonce storage excedeed
        $this->assertFalse($provider->validate($token0));
        $this->assertFalse($provider->validate($token1));
        $this->assertFalse($provider->validate($token2));
        $this->assertFalse($provider->validate($token3));
        $this->assertTrue($provider->validate($token4));
        $this->assertTrue($provider->validate($token5));
        $this->assertTrue($provider->validate($token6));
        $this->assertTrue($provider->validate($token7));
        $this->assertTrue($provider->validate($token8));
        $this->assertTrue($provider->validate($token9));
        $this->assertTrue($provider->validate($token10));
        $this->assertTrue($provider->validate($token11));
        $this->assertTrue($provider->validate($token12));
        $this->assertTrue($provider->validate($token13));

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

        $provider = new SynchronizerTokenProvider(storageSize: 5);
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

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

        $provider = new SynchronizerTokenProvider(storageSize: 5);
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        //genetate a token
        $token = $provider->getToken();
        $this->assertTrue($provider->validate($token));

        \session_write_close();

        // restart the session
        \session_start();

        $providerRestartedSession = new SynchronizerTokenProvider(storageSize: 5);
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

        $provider = new SynchronizerTokenProvider(storageSize: 5);
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        //genetate a token
        $token = $provider->getToken();
        $this->assertTrue($provider->validate($token));

        \session_destroy();

        // start the new session
        \session_start();

        $providerNewSession = new SynchronizerTokenProvider(storageSize: 5);
        $this->assertFalse($providerNewSession->validate($token));

        \session_destroy();
    }

    /**
     * Default time provider.
     * Provide time values to test when the token expires.
     *
     * @return array<array>
     */
    public static function defaultTimeProvider(): array
    {
        return [
            [605, false],
            [604, false],
            [603, false],
            [602, false],
            [601, false],
            [600, true],
            [599, true],
            [598, true],
            [597, true],
            [596, true],
            [595, true]
        ];
    }

        /**
     * Test verify token default expiration.
     *
     * @dataProvider defaultTimeProvider
     *
     * @runInSeparateProcess
     *
     * @return void
     */
    public function testVerifyTokenDefaultExpiration(int $timeIntervall, bool $expired): void
    {
        \session_start();

        //generate new token
        $token = \bin2hex(\random_bytes(\max(1, 16)));
        $time = \dechex(\time() - $timeIntervall);

        //store new token
        $_SESSION['csrf_syncronizer_token'][] = $token.$time;

        //create provider class
        $provider = new SynchronizerTokenProvider(tokenLength: 16);
        $this->assertInstanceOf(SynchronizerTokenProvider::class, $provider);

        $this->assertSame($expired, $provider->validate($token));
    }

    /**
     * Bad expire provider.
     * Provide expire time values out of range.
     *
     * @return array<array>
     */
    public static function badExpireProvider(): array
    {
        return [
            [-2, true],
            [-1, true],
            [0, false],
            [86400, false],
            [86401, true],
            [86402, true]
        ];
    }

    /**
     * Test new instance with wrong arguments for expire time.
     *
     * @dataProvider badExpireProvider
     *
     * @runInSeparateProcess
     *
     * @param int  $expire
     * @param bool $throw
     *
     * @return void
     */
    public function testNewInstanceWithBadExpire(int $expire, bool $throw): void
    {
        if ($throw) {
            $this->expectException(BadExpireException::class);
            $this->expectExceptionMessage('Expire time must be between 0 and 86400');

            (new SynchronizerTokenProvider(expire: $expire));
        }

        \session_start();
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(expire: $expire)));
        \session_destroy();
    }

    /**
     * Bad storage size provider.
     * Provide storage size values out of range.
     *
     * @return array<array>
     */
    public static function badStorageSizeProvider(): array
    {
        return [
            [0, true],
            [1, true],
            [2, false],
            [64, false],
            [65, true],
            [66, true],
        ];
    }

    /**
     * Test new instance with wrong arguments for storage size.
     *
     * @dataProvider badStorageSizeProvider
     *
     * @runInSeparateProcess
     *
     * @param int  $storageSize
     * @param bool $throw
     *
     * @return void
     */
    public function testNewInstanceWithBadStorageSize(int $storageSize, bool $throw): void
    {
        if ($throw) {
            $this->expectException(BadStorageSizeException::class);
            $this->expectExceptionMessage('Storage size must be between 2 and 64');

            (new SynchronizerTokenProvider(storageSize: $storageSize));
        }

        \session_start();
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(storageSize: $storageSize)));
        \session_destroy();
    }

    /**
     * Bad token length provider.
     * Provide token length values out of range.
     *
     * @return array<array>
     */
    public static function badTokenLengthProvider(): array
    {
        return [
            [14, true],
            [15, true],
            [16, false],
            [128, false],
            [129, true],
            [130, true]
        ];
    }

    /**
     * Test new instance with wrong arguments for token length.
     *
     * @dataProvider badTokenLengthProvider
     *
     * @runInSeparateProcess
     *
     * @param int  $tokenLength
     * @param bool $throw
     *
     * @return void
     */
    public function testNewInstanceWithBadTokenLength(int $tokenLength, bool $throw): void
    {
        if ($throw) {
            $this->expectException(BadTokenLengthException::class);
            $this->expectExceptionMessage('Token length must be between 16 and 128');

            (new SynchronizerTokenProvider(tokenLength: $tokenLength));
        }

        \session_start();
        $this->assertInstanceOf(SynchronizerTokenProvider::class, (new SynchronizerTokenProvider(tokenLength: $tokenLength)));
        \session_destroy();
    }
}
