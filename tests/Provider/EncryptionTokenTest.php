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
use Linna\CsrfGuard\Provider\EncryptionTokenProvider;
//use RuntimeException;
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
     */
    public function testNewInstance(): void
    {
        \session_start();

        //only session id
        $this->assertInstanceOf(EncryptionTokenProvider::class, (new EncryptionTokenProvider(\session_id())));
        //session id and expire time
        $this->assertInstanceOf(EncryptionTokenProvider::class, (new EncryptionTokenProvider(\session_id(), 300)));
        //session id, expire time and storage size
        $this->assertInstanceOf(EncryptionTokenProvider::class, (new EncryptionTokenProvider(\session_id(), 300, 32)));

        \session_destroy();
    }
}
