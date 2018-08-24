<?php

/**
 * Linna Array.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@alice.it>
 * @copyright (c) 2018, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Tests;

use InvalidArgumentException;
use Linna\CsrfGuard;
use RuntimeException;
use PHPUnit\Framework\TestCase;

/**
 * Cross-site Request Forgery Guard Test.
 */
class CsrfGuardTest extends TestCase
{
    /**
     * Test new instance.
     *
     * @runInSeparateProcess
     */
    public function testNewInstance(): void
    {
        session_start();

        $this->assertInstanceOf(CsrfGuard::class, (new CsrfGuard(64, 16)));

        session_destroy();
    }

    /**
     * Test new instance before session start.
     *
     * @expectedException RuntimeException
     */
    public function testNewInstanceBeforeSessionStart(): void
    {
        $this->assertInstanceOf(CsrfGuard::class, (new CsrfGuard(64, 16)));
    }

    /**
     * Contructor wrong arguments provider.
     *
     * @return array
     */
    public function contructorWrongArgumentsProvider(): array
    {
        return [
            ['64','16'],
            [true, false],
            [64.64, 16.16],
            [function () {
            },function () {
            }],
            [(object) ['name' => 'foo'], (object) ['name' => 'bar']],
            [[64], [16]],
        ];
    }

    /**
     * Test new instance with wrong arguments.
     *
     * @dataProvider contructorWrongArgumentsProvider
     * @expectedException TypeError
     */
    public function testNewInstanceWithWrongArguments($maxStorage, $tokenStrength): void
    {
        (new CsrfGuard($maxStorage, $tokenStrength));
    }

    /**
     * Test new instance with no arguments.
     *
     * @expectedException TypeError
     */
    public function testNewInstanceWithNoArguments(): void
    {
        (new CsrfGuard());
    }

    /**
     * Size limit provider.
     *
     * @return array
     */
    public function sizeLimitProvider(): array
    {
        return [[2], [4], [8], [16], [32], [64], [128], [3], [5], [9], [17], [33], [65], [129]];
    }

    /**
     * Test token limit.
     *
     * @dataProvider sizeLimitProvider
     * @runInSeparateProcess
     */
    public function testDequeue(int $sizeLimit): void
    {
        session_start();

        $csrf = new CsrfGuard($sizeLimit, 16);

        for ($i = 0; $i < $sizeLimit + 1; $i++) {
            $token = $csrf->getToken();
        }

        session_commit();
        session_start();

        $csrf = new CsrfGuard($sizeLimit, 16);

        $this->assertEquals($sizeLimit, count($_SESSION['CSRF']));

        session_destroy();
    }

    /**
     * Test get token.
     *
     * @runInSeparateProcess
     */
    public function testGetToken(): void
    {
        session_start();

        $csrf = new CsrfGuard(32, 16);

        $token = $csrf->getToken();

        $key = key($_SESSION['CSRF']);
        $value = $_SESSION['CSRF'][$key]['value'];

        $this->assertEquals($key, $token['name']);
        $this->assertEquals($value, $token['value']);

        session_destroy();
    }

    /**
     * Test get timed token.
     *
     * @runInSeparateProcess
     */
    public function testGetTimedToken(): void
    {
        session_start();

        $csrf = new CsrfGuard(32, 16);

        $token = $csrf->getTimedToken(5);
        $tokenTime = time() + 5;

        $key = key($_SESSION['CSRF']);
        $value = $_SESSION['CSRF'][$key]['value'];
        $time = $_SESSION['CSRF'][$key]['time'];

        $this->assertEquals($key, $token['name']);
        $this->assertEquals($value, $token['value']);
        $this->assertEquals($time, $token['time']);
        $this->assertEquals($tokenTime, $token['time']);

        session_destroy();
    }

    /**
     * Test validate.
     *
     * @runInSeparateProcess
     */
    public function testValidate(): void
    {
        session_start();

        $csrf = new CsrfGuard(32, 16);
        $csrf->getToken();

        $key = key($_SESSION['CSRF']);
        $token = $_SESSION['CSRF'][$key]['value'];

        $this->assertFalse($csrf->validate(['foo' => $token]));
        $this->assertFalse($csrf->validate([$key => 'foo']));
        $this->assertTrue($csrf->validate([$key => $token]));

        session_destroy();
    }

    /**
     * Test validate valid timed token.
     *
     * @runInSeparateProcess
     */
    public function testValidateValidTimedToken(): void
    {
        session_start();

        $csrf = new CsrfGuard(32, 16);
        $csrf->getTimedToken(2);

        $key = key($_SESSION['CSRF']);
        $token = $_SESSION['CSRF'][$key]['value'];

        $this->assertTrue($csrf->validate([$key => $token]));

        session_destroy();
    }

    /**
     * Test validate Expired timed token.
     *
     * @runInSeparateProcess
     */
    public function testValidateExiperdTimedToken(): void
    {
        session_start();

        $csrf = new CsrfGuard(32, 16);
        $csrf->getTimedToken(1);

        $key = key($_SESSION['CSRF']);
        $token = $_SESSION['CSRF'][$key]['value'];

        sleep(2);

        $this->assertFalse($csrf->validate([$key => $token]));

        session_destroy();
    }

    /**
     * Test token deletion after validation.
     *
     * @runInSeparateProcess
     */
    public function testDeleteTokenAfterValidation(): void
    {
        session_start();

        $csrf = new CsrfGuard(32, 16);
        $csrf->getToken();

        $key = key($_SESSION['CSRF']);
        $token = $_SESSION['CSRF'][$key]['value'];

        $this->assertTrue($csrf->validate([$key => $token]));
        //false means that the token was deleted from queque
        $this->assertFalse($csrf->validate([$key => $token]));

        session_destroy();
    }

    /**
     * Invalid token strength provider.
     *
     * @return array
     */
    public function invalidStrengthProvider(): array
    {
        return [[1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15]];
    }

    /**
     * Test token strength that it's less than 16.
     *
     * @param int $strength
     *
     * @dataProvider invalidStrengthProvider
     * @runInSeparateProcess
     */
    public function testGenerateTokenOnInvalidStrength(int $strength): void
    {
        session_start();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The minimum CSRF token strength is 16.');

        new CsrfGuard(32, $strength);

        session_destroy();
    }

    /**
     * Test token strength with valid values.
     *
     * @runInSeparateProcess
     */
    public function testGenerateTokenOnDefaultStrength(): void
    {
        session_start();

        $csrf = new CsrfGuard(32);
        $csrf->getToken();

        $key = key($_SESSION['CSRF']);
        $token = $_SESSION['CSRF'][$key]['value'];

        $this->assertEquals(32, strlen($token));
        $this->assertTrue($csrf->validate([$key => $token]));
        //false means that the token was deleted from queque
        $this->assertFalse($csrf->validate([$key => $token]));

        session_destroy();
    }

    /**
     * Valid token strength provider.
     *
     * @return array
     */
    public function validStrengthProvider(): array
    {
        $array = [];

        for ($i = 17; $i < 32; $i++) {
            $array[] = [$i, $i*2];
        }

        return $array;
    }

    /**
     * Test token strength with valid values.
     *
     * @dataProvider validStrengthProvider
     * @runInSeparateProcess
     */
    public function testGenerateTokenOnValidStrength($strength, $size): void
    {
        session_start();

        $csrf = new CsrfGuard(32, $strength);
        $csrf->getToken();

        $key = key($_SESSION['CSRF']);
        $token = $_SESSION['CSRF'][$key]['value'];

        $this->assertEquals($size, strlen($token));
        $this->assertTrue($csrf->validate([$key => $token]));
        //false means that the token was deleted from queque
        $this->assertFalse($csrf->validate([$key => $token]));

        session_destroy();
    }

    /**
     * Test Garbage Collector with wrong arguments.
     *
     * @expectedException TypeError
     *
     * @runInSeparateProcess
     */
    public function testGarbageCollectorWithWrongArgument(): void
    {
        session_start();

        $csrf = new CsrfGuard(4);
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();

        $csrf->garbageCollector(true);

        session_destroy();
    }

    /**
     * Test Garbage Collector with no arguments.
     *
     * @expectedException TypeError
     *
     * @runInSeparateProcess
     */
    public function testGarbageCollectorWithNoArgument(): void
    {
        session_start();

        $csrf = new CsrfGuard(32);
        $csrf->getToken();
        $csrf->garbageCollector();

        session_destroy();
    }

    /**
     * Test Garbage Collector with negative value as argument.
     *
     * @expectedException TypeError
     *
     * @runInSeparateProcess
     */
    public function testGarbageCollectorWithNegativeValueAsArgument(): void
    {
        session_start();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Argument value should be grater than zero.');

        $csrf = new CsrfGuard(4);
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->garbageCollector(-1);

        session_destroy();
    }

    /**
     * Test Garbage Collector with zero value as argument.
     *
     * @runInSeparateProcess
     */
    public function testGarbageCollectorWithZeroValueAsArgument(): void
    {
        session_start();

        $csrf = new CsrfGuard(4);
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->garbageCollector(0);

        //pass zero preserve all tokens
        $this->assertSame(4, count($_SESSION['CSRF']));

        session_destroy();
    }

    /**
     * Test Garbage Collector with value greater than storage as argument.
     *
     * @runInSeparateProcess
     */
    public function testGarbageCollectorWithValueGreatherThanStorageAsArgument(): void
    {
        session_start();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Argument value should be lesser than max storage value (4).');

        $csrf = new CsrfGuard(4);
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->getToken();
        $csrf->garbageCollector(5);

        session_destroy();
    }

    /**
     * Test garbage collector.
     *
     * @runInSeparateProcess
     */
    public function testGarbageCollector(): void
    {
        session_start();

        $csrf = new CsrfGuard(32);

        //fill the CSRF storage
        for ($i = 0; $i < 32; $i++) {
            $csrf->getToken();
            $this->assertSame($i+1, count($_SESSION['CSRF']));
        }

        $csrf->getToken();
        $this->assertSame(32, count($_SESSION['CSRF']));

        $csrf->getToken();
        $this->assertSame(32, count($_SESSION['CSRF']));

        $csrf->garbageCollector(2);
        $this->assertSame(2, count($_SESSION['CSRF']));

        $csrf->getToken();
        $this->assertSame(3, count($_SESSION['CSRF']));

        $csrf->getToken();
        $this->assertSame(4, count($_SESSION['CSRF']));

        $csrf->getToken();
        $csrf->garbageCollector(2);
        $this->assertSame(5, count($_SESSION['CSRF']));

        session_destroy();
    }

    /**
     * Test clean.
     *
     * @runInSeparateProcess
     */
    public function testClean(): void
    {
        session_start();

        $csrf = new CsrfGuard(32);

        //fill the CSRF storage
        for ($i = 0; $i < 32; $i++) {
            $csrf->getToken();
            $this->assertSame($i+1, count($_SESSION['CSRF']));
        }

        $csrf->getToken();
        $this->assertSame(32, count($_SESSION['CSRF']));

        $csrf->getToken();
        $this->assertSame(32, count($_SESSION['CSRF']));

        $csrf->clean(2);
        $this->assertSame(2, count($_SESSION['CSRF']));

        $csrf->getToken();
        $this->assertSame(3, count($_SESSION['CSRF']));

        $csrf->getToken();
        $this->assertSame(4, count($_SESSION['CSRF']));

        $csrf->getToken();
        $csrf->clean(2);
        $this->assertSame(2, count($_SESSION['CSRF']));

        session_destroy();
    }
}
