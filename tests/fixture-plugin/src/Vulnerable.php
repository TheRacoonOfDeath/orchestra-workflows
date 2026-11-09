<?php

/*
 * Deliberately vulnerable code for the self-test of the security scan. Never include it anywhere.
 */

declare(strict_types=1);

namespace Orchestra\Fixture;

final class Vulnerable
{
    public function __construct(private readonly \wpdb $wpdb)
    {
    }

    public function greeting(): string
    {
        return 'Hello ' . (string) $_GET['name'];
    }

    public function render(): void
    {
        echo $this->greeting();
    }

    public function find(): mixed
    {
        return $this->wpdb->get_results('SELECT * FROM wp_users WHERE user_login = "' . (string) $_POST['login'] . '"');
    }
}
