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
use Linna\CsrfGuard\Provider\HmacTokenProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cross-site Request Forgery Guard
 * Hmac Token Provider Test
 */
class HmacTokenProviderTest extends TestCase
{
    /** @var string $value Value will be hashed inside token */
    private static $value = "value_to_be_hashed";

    /** @var string $key Secret key for the hmac */
    private static $key = "strong_secret_key";

    /**
     * Test new instance.
     */
    public function testNewInstance(): void
    {
        //only session id
        $this->assertInstanceOf(HmacTokenProvider::class, (new HmacTokenProvider(self::$value, self::$key)));
        //session id and expire time
        $this->assertInstanceOf(HmacTokenProvider::class, (new HmacTokenProvider(self::$value, self::$key, 300)));
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

        (new HmacTokenProvider(self::$value, self::$key, $expire));
    }

    /**
     * Test method get token.
     *
     * @return void
     */
    public function testGetToken(): void
    {
        $provider = new HmacTokenProvider(self::$value, self::$key);

        $token = $provider->getToken();

        $this->assertSame(\strlen($token), 108);
    }

    /**
     * Test method validate.
     *
     * @return void
     */
    public function testValidate(): void
    {
        $provider = new HmacTokenProvider(self::$value, self::$key);

        $this->assertTrue($provider->validate($provider->getToken()));
    }

    /**
     * Test method validate passing a void token.
     *
     * @return void
     */
    public function testValidateVoidToken(): void
    {
        $provider = new HmacTokenProvider(self::$value, self::$key);

        $this->assertFalse($provider->validate(""));
    }

    /**
     * Test method validate passing a tampered token.
     *
     * @return void
     */
    public function testValidateBadToken(): void
    {
        $provider = new HmacTokenProvider(self::$value, self::$key);

        $token = $provider->getToken();
        //alter first 4 chars of the token
        $token[0] = "0";
        $token[1] = "0";
        $token[2] = "0";
        $token[3] = "0";

        $this->assertFalse($provider->validate($token));
    }

    /**
     * Test method validate passing an expired token.
     *
     * @return void
     */
    public function testValidateExpiredToken(): void
    {
        $provider = new HmacTokenProvider(self::$value, self::$key);

        //craft a token expired 10 seconds ago
        $time = \base_convert((string) (\time() - 610), 10, 16);
        $random = \bin2hex(\random_bytes(2));
        $token = \hash_hmac('sha3-384', self::$value.$time.$random, self::$key).$time.$random;

        $this->assertFalse($provider->validate($token));
    }

    /**
     * Time provider.
     * Provide time values to test when the token expires.
     *
     * @return array<array>
     */
    public function timeProvider(): array
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
     * Test method validate expire boundary.
     *
     * @dataProvider timeProvider
     *
     * @param int  $spread
     * @param bool $test
     *
     * @return void
     */
    public function testValidateExpireBoundary(int $spread, bool $test): void
    {
        $provider = new HmacTokenProvider(self::$value, self::$key);

        //craft the token
        $time = \base_convert((string) (\time() - $spread), 10, 16);
        $random = \bin2hex(\random_bytes(2));
        $token = \hash_hmac('sha3-384', self::$value.$time.$random, self::$key).$time.$random;

        $this->assertSame($test, $provider->validate($token));
    }
}
