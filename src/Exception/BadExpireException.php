<?php

/**
 * Linna Cross-site Request Forgery Guard
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\CsrfGuard\Exception;

use RangeException;

/**
 * Bad Expire Exception.
 * Exception thrown to indicate an error about expire time for a token provider.
 */
class BadExpireException extends RangeException
{
}
