<?php

declare(strict_types=1);

/**
 * This file is part of the Linna Csrf Guard.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */

namespace Linna\CsrfGuard\Exception;

use RangeException;

/**
 * Bad Expire Exception.
 *
 * <p>Exception thrown to indicate an error about expire time configuration in a token provider.</p>
 */
class BadExpireException extends RangeException
{
}
