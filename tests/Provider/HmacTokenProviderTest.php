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
use Linna\CsrfGuard\Provider\HmacTokenProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cross-site Request Forgery Guard
 * Hmac Token Provider Test
 */
class HmacTokenProviderTest extends TestCase
{
    /**
     * Test new instance.
     *
     */
    public function testNewInstance(): void
    {
        //only session id
        $this->assertInstanceOf(HmacTokenProvider::class, (new HmacTokenProvider("value_to_be_hashed", "strong_secret_key")));
        //session id and expire time
        $this->assertInstanceOf(HmacTokenProvider::class, (new HmacTokenProvider("value_to_be_hashed", "strong_secret_key", 300)));
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

        (new HmacTokenProvider("value_to_be_hashed", "strong_secret_key", $expire));
    }
}
