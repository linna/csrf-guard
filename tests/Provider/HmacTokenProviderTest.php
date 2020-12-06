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

//use InvalidArgumentException;
use Linna\CsrfGuard\Provider\HmacTokenProvider;
//use RuntimeException;
use PHPUnit\Framework\TestCase;

//use TypeError;

/**
 * Cross-site Request Forgery Guard
 * Hmac Token Provider Test
 */
class HmacTokenProviderTest extends TestCase
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
        $this->assertInstanceOf(HmacTokenProvider::class, (new HmacTokenProvider(\session_id(), "strong_secret_key")));
        //session id and expire time
        $this->assertInstanceOf(HmacTokenProvider::class, (new HmacTokenProvider(\session_id(), "strong_secret_key", 300)));

        \session_destroy();
    }
}
