<?php

/*
 * Deliberately vulnerable plugin for the self-test of the security scan. Never install it.
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

(new Orchestra\Fixture\Vulnerable($GLOBALS['wpdb']))->render();
