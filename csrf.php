<?php

namespace kafene;

/**
 * kafene\csrf;
 *
 * This is a class for making and validating CSRF tokens
 * I let it run automatically, every "non-safe" request
 * (not HEAD, OPTIONS, GET) MUST have a token, or it is discarded.
 * It's kind of sparsely commented but should be easy enough to figure out.
 * Oh and all the methods are static :-)
 *
 * @todo use hash_hmac
 * @todo multiple tokens
 *
 * @link https://github.com/kafene/csrf
 * @version 20130517
 * @license Public Domain <http://unlicense.org/>
 * @copyright Waived
 */
class csrf {
    static $lastToken;

    static function init() {
        static $init = true;

        if ($init) {
            if (PHP_SESSION_ACTIVE !== session_status()) {
                session_start();
            }

            if (empty($_SESSION['CSRF::Tokens'])) {
                $_SESSION['CSRF::Tokens'] = [];
            } else {
                # Garbage collection
                foreach ($_SESSION['CSRF::Tokens'] as $md5 => $val) {
                    if (time() > $val['expires']) {
                        unset($_SESSION['CSRF::Tokens'][$md5]);
                    }
                }
            }

            $init = false;
        }
    }

    static function getToken($ttl = 300) {
        static::init();

        if ($ttl && !empty(static::$lastToken)) {
            $k = static::$lastToken;

            if (!empty($_SESSION['CSRF::Tokens'][$k])) {
                return $_SESSION['CSRF::Tokens'][$k]['nonce'];
            }
        }

        $nonce = openssl_random_pseudo_bytes(32);
        $expires = $ttl ? (time() + $ttl) : false;
        $ip = getenv('REMOTE_ADDR');

        static::$lastToken = $i = md5($nonce);

        $nonce = static::encode($nonce);
        $_SESSION['CSRF::Tokens'][$i] = compact('nonce', 'expires', 'ip');

        return $nonce;
    }

    static function checkToken(&$token) {
        static::init();

        if (empty($token)) {
            return false;
        }

        $token = static::decode($token);
        $i = md5($token);

        if (empty($_SESSION['CSRF::Tokens'][$i])) {
            return false;
        }

        $valid = $_SESSION['CSRF::Tokens'][$i];
        $_SESSION['CSRF::Tokens'] = [];

        return (0 === strcmp($token, static::decode($valid['nonce'])))
            && ($valid['ip'] === $_SERVER['REMOTE_ADDR'])
            && ($valid['expires'] === false || (time() < $valid['expires']));
    }

    static function requestMethodIsSafe($method = null) {
        $method = $method ?: strtoupper(getenv('REQUEST_METHOD'));

        return in_array($method, ['HEAD', 'GET', 'OPTIONS'], true);
    }

    # Base64, but URL-ready.
    static function encode($value) {
        return strtr(base64_encode($value), '+/=', '-_~');
    }

    static function decode($value) {
        return base64_decode(strtr($value, '-_~', '+/='));
    }

    static function protect() {
        # We don't need to run protection if the method is 'safe'.
        if (static::requestMethodIsSafe() && empty($_POST)) return;

        $token = static::detectToken();

        if (!$token || !static::checkToken($token)) {
            throw new \UnexpectedValueException('CSRF Token Invalid');
        }

        return true;
    }

    # Wraps 3 ways of detecting the token and returns any that was found.
    static function detectToken() {
        if ($token = getenv('HTTP_X_CSRF_TOKEN')) {
            return $token;
        }
 
        if ($token = getenv('HTTP_X_REQUEST_TOKEN')) {
            return $token;
        }

        if (!empty($_POST['token'])) {
            return (string) $_POST['token'];
        }

        if (!static::requestMethodIsSafe() && !empty($_REQUEST['token'])) {
            return (string) $_REQUEST['token'];
        }
    }
}


# Example:

CSRF::protect();
ob_get_level() || ob_start();

?><!DOCTYPE html>
<form method="POST" action="">
<input type="text" name="clue" value="whatever">
<input type="hidden" name="token" value="<?= CSRF::getToken(); ?>">
<input type="submit">
</form>
