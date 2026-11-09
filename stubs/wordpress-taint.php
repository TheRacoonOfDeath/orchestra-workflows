<?php

/*
 * Taint annotations for the WordPress functions the Orchestra plugins use, loaded after
 * php-stubs/wordpress-stubs. They tell Psalm's taint analysis where user input becomes dangerous
 * (sinks) and which functions make it safe (escapes). Signatures follow WordPress.
 */

// phpcs:ignoreFile

class wpdb
{
    /**
     * @psalm-taint-sink sql $query
     */
    public function query($query) {}

    /**
     * @psalm-taint-sink sql $query
     */
    public function get_results($query = null, $output = OBJECT) {}

    /**
     * @psalm-taint-sink sql $query
     */
    public function get_row($query = null, $output = OBJECT, $y = 0) {}

    /**
     * @psalm-taint-sink sql $query
     */
    public function get_col($query = null, $x = 0) {}

    /**
     * @psalm-taint-sink sql $query
     */
    public function get_var($query = null, $x = 0, $y = 0) {}

    /**
     * The query is a format string: only the placeholders may carry input.
     *
     * @psalm-taint-sink sql $query
     * @psalm-taint-escape sql
     */
    public function prepare($query, ...$args) {}

    /**
     * @psalm-taint-escape sql
     */
    public function esc_like($text) {}
}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function esc_html($text) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function esc_attr($text) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function esc_textarea($text) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function esc_html__($text, $domain = 'default') {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function esc_attr__($text, $domain = 'default') {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function esc_js($text) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 * @psalm-taint-escape header
 */
function esc_url($url, $protocols = null, $_context = 'display') {}

/**
 * @psalm-taint-escape header
 */
function esc_url_raw($url, $protocols = null) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function wp_kses($content, $allowed_html, $allowed_protocols = []) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function wp_kses_post($data) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 * @psalm-taint-escape sql
 */
function sanitize_key($key) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function sanitize_html_class($classname, $fallback = '') {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function sanitize_email($email) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 * @psalm-taint-escape file
 */
function sanitize_file_name($filename) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 * @psalm-taint-escape sql
 */
function absint($maybeint) {}

/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function wp_json_encode($value, $flags = 0, $depth = 512) {}

/**
 * Only redirects to allowed hosts.
 *
 * @psalm-taint-escape header
 */
function wp_safe_redirect($location, $status = 302, $x_redirect_by = 'WordPress') {}

/**
 * @psalm-taint-sink header $location
 */
function wp_redirect($location, $status = 302, $x_redirect_by = 'WordPress') {}
