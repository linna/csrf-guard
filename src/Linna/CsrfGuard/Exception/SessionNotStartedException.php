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

use LogicException;

/**
 * Session not started Exception.
 * 
 * <p>Exception thrown to indicate that a token provider require a session and the session isn't started.</p>
 */
class SessionNotStartedException extends LogicException
{
}
