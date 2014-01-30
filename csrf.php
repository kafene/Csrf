<?php

namespace kafene;



/*
 * Exception thrown when an invalid or missing CSRF Token is detected.
 */
class CsrfException extends \Exception {}



/**
 * kafene\Csrf
 * A class for preventing CSRF (Cross-site request forgery) attacks.
 * Original CSRF methodology is inspired by ircmaxell (PHP internals developer)
 * @see http://blog.ircmaxell.com/2013/02/preventing-csrf-attacks.html
 *
 * @copyright (c) 2013, Matthew Covey <matt@kafene.org>
 * @license MIT <http://kafene.mit-license.org/>
 */
class Csrf
{
    /**
     * @var string The key used in the $_SESSION array for holding CSRF Tokens
     */
    protected $key = "csrf_tokens";

    /**
     * @var string The last generated token.
     */
    protected $hash = "";

    /**
     * @var integer The time period for which a CSRF Token is valid.
     *
     * Default of 600  = 10 minutes.
     */
    protected $ttl = 600;

    /**
     * @var string The PHP hash() algorithm used to generate the token.
     */
    protected $hashAlgorithm = "whirlpool";

    /**
     * @var string The default CSRF request parameter to look for in POST data.
     */
    protected $requestParam = "csrf_token";

    /**
     * @var string The default CSRF variable for $_SERVER.
     *
     * The CSRF token can be sent as an HTTP header as an alternative to
     * a request parameter, or alongside it. Either, or both can be used.
     * To send the header instead of a request param, f/e in jQuery,
     * use `{headers: {"X-CSRF-Token": "... csrf token value ..."}}`.
     */
    protected $serverParam = "HTTP_X_CSRF_TOKEN";



    /**
     * Constructor
     *
     * @param string $key - the $_SESSION key to be used for holding CSRF tokens.
     */
    public function __construct($key = "csrf_tokens")
    {
        // A session is required. If we're using PHP 5.4+, then the
        // session_status() function is the best way to detect if one
        // has already been started.
        if (version_compare(PHP_VERSION, '5.4.0') >= 0) {
            if (PHP_SESSION_ACTIVE !== session_status()) {
                session_start();
            }
        } elseif (!session_id()) {
            session_start();
        }

        $this->key = $key;

        // Initialize $_SESSION[$key] to an empty array
        if (empty($_SESSION[$this->key])) {
            $_SESSION[$this->key] = array();
        }
    }


    /** Setters and getters **/


    /**
     * Set the `ttl` value
     *
     * @param integer $ttl The time after which a token is considered expired.
     *
     * @return static $this
     */
    public function setTtl($ttl)
    {
        if (!is_int($ttl)) {
            throw new \InvalidArgumentException('TTL must be an integer.');
        } else {
            $this->ttl = $ttl;
        }

        return $this;
    }

    /**
     * Get the `ttl` value
     *
     * @return integer $ttl
     */
    public function getTtl()
    {
        return (int) $this->ttl;
    }

    /**
     * Set the `requestParam` value
     *
     * @param string $requestParam The new requestParam value
     *
     * @throws \InvalidArgumentException if the request parameter contains
     *     a `[` or `]` character (that is, it must not be an array, only a
     *     single value is allowed) or if it is not a string.
     *
     * @return static $this
     */
    public function setRequestParam($requestParam)
    {
        if (!is_string($requestParam) || preg_match('/\[\]/', $requestParam)) {
            throw new \InvalidArgumentException('Invalid request parameter name.');
        } else {
            $this->requestParam = $requestParam;
        }

        return $this;
    }

    /**
     * Get the `requestParam` value
     *
     * @return string The `requestParam` value
     */
    public function getRequestParam()
    {
        return $this->requestParam;
    }

    /**
     * Set the `serverParam` value.
     *
     * @param string $serverParam
     *     Either a header in the form of "X-Foo-Bar"
     *     OR a PHP header as found in $_SERVER - HTTP_X_FOO_BAR
     *
     * @return static $this
     */
    public function setServerParam($serverParam)
    {
        // Translate f/e X-Csrf-Token into X_CSRF_TOKEN
        $serverParam = strtoupper(str_replace('-', '_', $serverParam));

        // Add HTTP_ prefix.
        if (0 !== strpos($serverParam, 'HTTP_')) {
            $serverParam = 'HTTP_' . $serverParam;
        }

        $this->serverParam = $serverParam;
    }

    /**
     * Get the `serverParam` value
     *
     * @param string $format - If the format is "php", the param name will
     *     be returned in the PHP $_SERVER format like HTTP_X_FOO_BAR,
     *     if it is "http" it will be returned like an HTTP header - X-Foo-Bar.
     *     The default is "php".
     *
     * @throws \InvalidArgumentException if an invalid $format is given.
     *
     * @return string the serverParam value.
     */
    public function getServerParam($format = 'php')
    {
        if ($format === 'http') {
            // Translate HTTP_X_FOO to X-Foo
            $serverParam = $this->serverParam;
            $serverParam = strtolower($serverParam);
            $parts = explode('_', $serverParam);
            $parts = array_map('ucfirst', $parts);
            $serverParam = join('-', $parts);

            return $serverParam;
        } elseif ($format === 'php') {
            return $this->serverParam;
        } else {
            throw new \InvalidArgumentException('Unrecognized serverParam format.');
        }
    }

    /**
     * Set the `hashAlgorithm` value - the algorithm used by the hash() function.
     *
     * @param string $hashAlgorithm The algorithm to use, f/e whirlpool.
     *     The default algorithm for this class is whirlpool.
     *
     * @throws \InvalidArgumentException if the hash algorithm is not supported
     *     by the current PHP installation (that is, it is not in hash_algos()).
     *
     * @return static $this
     */
    public function setHashAlgorithm($hashAlgorithm)
    {
        if (!in_array($hashAlgorithm, hash_algos())) {
            $err = 'The installed version of PHP does not support '
                 . 'the given hash algorithm.';

            throw new \InvalidArgumentException($err);
        } else {
            $this->hashAlgorithm = $hashAlgorithm;
        }

        return $this;
    }

    /**
     * Get the `hashAlgorithm` value.
     *
     * @return string The hash algorithm
     */
    public function getHashAlgorithm()
    {
        return $this->hashAlgorithm();
    }


    /** Public API **/


    /**
     * Get a CSRF token. If one has been generated and the `new` parameter is
     * not set to true, the previously generated token will be used, so the
     * same token is referenced during the request unless explicitly changed.
     *
     * @param boolean $new Whether to force generating a new token.
     *
     * @return string The value of the token to pass to the client.
     */
    public function getToken($new = false)
    {
        if (!empty($this->hash) && !$new) {
            return $this->hash;
        }

        $token = new \stdClass();
        $token->nonce = $this->createNonce();
        $token->userData = $this->getUserData();
        $token->expires = $this->ttl ? (time() + intval($this->ttl)) : false;

        // Raw token is json, stored in $_SESSION
        $token = json_encode($token);

        // Hash of token is taken to pass to client
        $hash = hash($this->hashAlgorithm, $token);

        $_SESSION[$this->key][$hash] = $token;
        $this->hash = $hash;

        return $hash;
    }

    /**
     * Validate a token passed in the client's request.
     *
     * @param string $hash The client token from the request.
     *     If this is left empty, attempt to detect the token from
     *     the request.
     *
     * @return boolean Whether the token is valid or not.
     */
    public function validateToken($hash = null)
    {
        $hash = $hash ?: $this->findToken();

        if (
            empty($_SESSION[$this->key]) ||
            empty($hash) ||
            empty($_SESSION[$this->key][$hash])
        ) {
            return false;
        }

        $token = $_SESSION[$this->key][$hash];
        unset($_SESSION[$this->key][$hash]);

        try {
            $token = json_decode($token);

            // Force invalidation if json_decode isn't throwing.
            if (JSON_ERROR_NONE !== json_last_error()) {
                throw new \Exception();
            }
        } catch (\Exception $e) {
            // Invalid json
            return false;
        }

        $userDataMatch = $this->getUserData() === $token->userData;
        $isExpired = $token->expires && time() > intval($token->expires);

        return ($userDataMatch && !$isExpired);
    }

    /**
     * Check a token's validity and throw an exception if it is invalid.
     * This is more secure than testing with `validateToken` since it
     * will force execution to stop unless it is caught.
     *
     * @param string $hash The client token from the request.
     *     If this is left empty, attempt to detect the token from
     *     the request.
     *
     * @throws kafene\CsrfException if the token is invalid.
     *
     * @return true if the CSRF validation passed.
     */
    public function check($hash = null)
    {
        $hash = $hash ?: ($this->findToken() ?: null);

        if (empty($hash) || true !== $this->validateToken($hash)) {
            throw new CsrfException("Invalid CSRF Token.");
        } else {
            return true;
        }
    }

    /**
     * Attempt to find the token from a client's header or $_POST data.
     * NOTE: If using a method like PUT or DELETE, either the raw data
     * should be merged into $_POST, the header field used, or this method
     * should be avoided, as it will not otherwise work.
     *
     * @return string|null The CSRF token hash, if found, or null.
     */
    public function findToken()
    {
        if (!empty($_SERVER[$this->serverParam])) {
            return (string) $_SERVER[$this->serverParam];
        } elseif (!empty($_POST[$this->requestParam])) {
            return (string) $_POST[$this->requestParam];
        }
    }

    /**
     * Automatically run CSRF protection via `$this->check()` on all
     * non-idempotent methods. This includes POST, PUT, DELETE, and PATCH.
     *
     * @param array $methods Alternative methods to run on if the defaults are
     *     not acceptable.
     *
     * @return null
     */
    public function protect($methods = array('POST', 'PUT', 'DELETE', 'PATCH'))
    {
        $requestMethod = isset($_SERVER["REQUEST_METHOD"])
            ? strtoupper($_SERVER["REQUEST_METHOD"])
            : "POST";

        if (in_array($requestMethod, $methods)) {
            $this->check();
        }
    }

    /**
     * Convenience method for getting an HTML <input> tag with the current
     * request token in it.
     *
     * @return string the HTML <input> tag.
     */
    public function formInput()
    {
        $format = '<input type="hidden" name="%s" value="%s">' . "\n";

        return sprintf($format, $this->requestParam, $this->getToken());
    }

    /**
     * Convenience method for getting an HTML <meta> tag with the current
     * request token in it, usually for detection by javascript.
     *
     * @return string the HTML <input> tag.
     */
    public function metaTag()
    {
        $format = '<meta name="%s" content="%s">' . "\n";

        return sprintf($format, $this->serverParam, $this->getToken());
    }


    /** Protected Methods **/


    /**
     * Create a nonce value for use in the token.
     * Try to use OpenSSL if possible, if not fall back to mcrypt.
     *
     * @param string $bytes Number of bytes the raw token should contain.
     *
     * @return string the base64 encoded raw binary token value.
     */
    protected function createNonce($bytes = 64)
    {
        $nonce = function_exists("openssl_random_pseudo_bytes")
            ? openssl_random_pseudo_bytes($bytes)
            : mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);

        return base64_encode($nonce);
    }

    /**
     * Get unique per-request user data to match with future requests.
     * The most consistent unique values are the user's IP address and,
     * if set, the browser (user agent).
     *
     * @return string A hash of the unique user data.
     */
    protected function getUserData()
    {
        $keys = array("REMOTE_ADDR", "HTTP_USER_AGENT");
        $userData = array();

        foreach ($keys as $key) {
            if (!empty($_SERVER[$key])) {
                $userData[] = $_SERVER[$key];
            }
        }

        $userData = serialize($userData);
        $userData = hash($this->hashAlgorithm, $userData);

        return $userData;
    }
}
