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

/**
 * Session not started trait.
 *
 * <p>Provide a method to check conditions to throw SessionNotStartedException.</p>
 */
trait SessionNotStartedTrait
{
    /**
     * Check if session isn't started.
     *
     * @return void
     *
     * @throws SessionNotStartedException If sessions are disabled or not started.
     */
    final protected function checkSessionNotStarted(): void
    {
        if (\session_status() !== PHP_SESSION_ACTIVE) {
            throw new SessionNotStartedException('Session not started, enable it and start one before use this token provider');
        }
    }
}
