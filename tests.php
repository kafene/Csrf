<?php

test("Csrf::__construct() starts a session if one is not already started", function () {
    $csrf = new \kafene\Csrf();
    assert(session_status() === PHP_SESSION_ACTIVE);
});

test("Csrf::__construct() uses a different session key if set.", function () {
    $csrf = new \kafene\Csrf('foo');
    $key = new \ReflectionProperty($csrf, 'key');
    $key->setAccessible(true);
    assert($key->getValue($csrf) === 'foo');
});

test("Csrf::__construct() intializes the session key.", function () {
    $csrf = new \kafene\Csrf('bar');
    assert(is_array($_SESSION['bar']));
});

test("Csrf::setTtl() throws an exception for invalid TTL values.", function () {
    $csrf = new \kafene\Csrf();
    $caught = false;

    try {
        $csrf->setTtl('2 days');
    } catch (\InvalidArgumentException $e) {
        $caught = true;
        assert($e->getMessage() === 'TTL must be an integer.');
    }

    assert(true === $caught);
});

test("Csrf::setTtl() accepts a time value using strtotime.", function () {
    $csrf = new \kafene\Csrf();
    $ttl = strtotime("+2 days", 0);
    $csrf->setTtl($ttl);
    assert($csrf->getTtl() === 2 * 86400);
});

test("Csrf::setTtl() and Csrf::getTtl() work as expected.", function () {
    $csrf = new \kafene\Csrf();
    $csrf->setTtl(500);
    assert(500 === $csrf->getTtl());
});

test("Csrf::setRequestParam() throws an exception for invalid values.", function () {
    $csrf = new \kafene\Csrf();
    $caught1 = false;
    $caught2 = false;

    try {
        $csrf->setRequestParam("foo[]");
    } catch (\InvalidArgumentException $e) {
        $caught1 = true;
        assert($e->getMessage() === 'Invalid request parameter name.');
    }

    try {
        $csrf->setRequestParam(PHP_INT_SIZE);
    } catch (\InvalidArgumentException $e) {
        $caught2 = true;
        assert($e->getMessage() === 'Invalid request parameter name.');
    }

    assert($caught1 === true && $caught2 === true);
});

test("Csrf::setRequestParam() and Csrf::getRequestParam() work as expected.", function () {
    $csrf = new \kafene\Csrf();
    $csrf->setRequestParam('foo');
    assert($csrf->getRequestParam() === 'foo');
});

test("Csrf::setServerParam() and Csrf::getServerParam() work properly.", function () {
    $csrf = new \kafene\Csrf();
    $csrf->setServerParam("HTTP_X_FOO_BAR");
    assert($csrf->getServerParam("http") === "X-Foo-Bar");
    assert($csrf->getServerParam("php") === "HTTP_X_FOO_BAR");
    $csrf->setServerParam("X-Foo-Bar");
    assert($csrf->getServerParam("http") === "X-Foo-Bar");
    assert($csrf->getServerParam("php") === "HTTP_X_FOO_BAR");
});

test("Csrf::getServerParam() throws an exception given an invalid format.", function () {
    $csrf = new \kafene\Csrf();
    $caught = false;

    try {
        $csrf->getServerParam("json");
    } catch (\InvalidArgumentException $e) {
        $caught = true;
        assert($e->getMessage() === 'Unrecognized serverParam format.');
    }

    assert($caught === true);
});

test("Csrf::setHashAlgorithm() throws an exception for invalid algorithms.", function () {
    $csrf = new \kafene\Csrf();
    $caught = false;

    try {
        $csrf->setHashAlgorithm(MCRYPT_RIJNDAEL_256);
    } catch (\InvalidArgumentException $e) {
        $caught = true;
        assert($e->getMessage() === 'The installed version of PHP does not support the given hash algorithm.');
    }

    assert($caught === true);
});

test("Csrf::setHashAlgorithm() sets the hash algorithm properly.", function () {
    $csrf = new \kafene\Csrf();
    $csrf->setHashAlgorithm('sha512');
    assert($csrf->getHashAlgorithm() === 'sha512');
});

test("Csrf::getToken() returns a token when none has been generated yet.", function () {
    $csrf = new \kafene\Csrf();

    $hash = $csrf->getToken();

    $key = new \ReflectionProperty($csrf, 'key');
    $key->setAccessible(true);
    $key = $key->getValue($csrf);

    assert(!empty($hash));
    assert(!empty($_SESSION[$key][$hash]));
    assert(is_object(json_decode($_SESSION[$key][$hash])));
});

test("Csrf::getToken() returns the same token for the current request.", function () {
    $csrf = new \kafene\Csrf();

    $hash1 = $csrf->getToken();
    $hash2 = $csrf->getToken();

    assert($hash1 === $hash2);
});

test("Csrf::getToken() returns a fresh token if the 'new' parameter is true.", function () {
    $csrf = new \kafene\Csrf();

    $hash1 = $csrf->getToken();
    $hash2 = $csrf->getToken(true);
    $hash3 = $csrf->getToken();

    assert($hash1 != $hash2);
    assert($hash2 === $hash3);
});

test("Csrf::validateToken() returns false for invalid JSON.", function () {
    $csrf = new \kafene\Csrf();

    $hash = 'CsrfTestHash1PlzIgnore';
    $key = "csrf_tokens";

    $_SERVER['HTTP_X_CSRF_TOKEN'] = $hash;
    $_SESSION[$key][$hash] = 'malformed \\\\ json';

    $result = $csrf->validateToken();

    assert(false === $result);
    assert(JSON_ERROR_NONE !== json_last_error());
});

test("Csrf::validateToken() returns false and Csrf::check() throws a kafene\CsrfException for a bad token.", function () {
    $csrf = new \kafene\Csrf();

    $key = new \ReflectionProperty($csrf, 'key');
    $key->setAccessible(true);
    $key = $key->getValue($csrf);

    $_SERVER['HTTP_X_CSRF_TOKEN'] = 'wrong token 1';
    $_SESSION[$key]['bad_token'] = '{}';

    assert(false === $csrf->validateToken());
    assert(false === $csrf->validateToken('wrong token 2'));

    $caught1 = false;
    $caught2 = false;

    try {
        $csrf->check();
    } catch (\kafene\CsrfException $e) {
        $caught1 = true;
        assert($e->getMessage() === 'Invalid CSRF Token.');
    }

    try {
        $csrf->check('wrong token 3');
    } catch (\kafene\CsrfException $e) {
        $caught2 = true;
        assert($e->getMessage() === 'Invalid CSRF Token.');
    }

    assert($caught1 === true);
    assert($caught2 === true);
});

test("Csrf::validateToken() and Csrf::check() work on a correct token", function () {
    $csrf = new \kafene\Csrf();

    $key = new \ReflectionProperty($csrf, 'key');
    $key->setAccessible(true);
    $key = $key->getValue($csrf);

    $getUserData = new \ReflectionMethod($csrf, 'getUserData');
    $getUserData->setAccessible(true);
    $userData = $getUserData->invoke($csrf);

    $createNonce = new \ReflectionMethod($csrf, 'getUserData');
    $createNonce->setAccessible(true);
    $nonce = $createNonce->invoke($csrf);

    $token = new \stdClass();
    $token->nonce = $nonce;
    $token->userData = $userData;
    $token->expires = time() + intval($csrf->getTtl());
    $token = json_encode($token);
    $hash = hash($csrf->getHashAlgorithm(), $token);

    $_SESSION[$key][$hash] = $token;
    $_SERVER['HTTP_X_CSRF_TOKEN'] = $hash;

    assert(false !== $csrf->validateToken());
    assert(JSON_ERROR_NONE === json_last_error());

    $_SESSION[$key][$hash] = $token;
    $_SERVER['HTTP_X_CSRF_TOKEN'] = $hash;

    assert(false !== $csrf->validateToken($hash));
    assert(JSON_ERROR_NONE === json_last_error());

    $_SESSION[$key][$hash] = $token;
    $_SERVER['HTTP_X_CSRF_TOKEN'] = $hash;

    assert(true === $csrf->check());
    assert(JSON_ERROR_NONE === json_last_error());

    $_SESSION[$key][$hash] = $token;
    $_SERVER['HTTP_X_CSRF_TOKEN'] = $hash;

    assert(true === $csrf->check($hash));
    assert(JSON_ERROR_NONE === json_last_error());
});

test("Csrf::findToken() works when a compatible param exists.", function () {
    $csrf = new \kafene\Csrf();

    $_SERVER['HTTP_X_CSRF_TOKEN'] = 'foo';
    assert($csrf->findToken() === 'foo');
    unset($_SERVER['HTTP_X_CSRF_TOKEN']);

    $_POST['csrf_token'] = 'bar';
    assert($csrf->findToken() === 'bar');
    unset($_POST['csrf_token']);

    $csrf->setServerParam('X-Server-Param');
    $_SERVER['HTTP_X_SERVER_PARAM'] = 'baz';
    assert($csrf->findToken() === 'baz');
    unset($_SERVER['HTTP_X_SERVER_PARAM']);

    $csrf->setServerParam('HTTP_X_SERVER_PARAM');
    $_SERVER['HTTP_X_SERVER_PARAM'] = 'baz';
    assert($csrf->findToken() === 'baz');
    unset($_SERVER['HTTP_X_SERVER_PARAM']);

    $csrf->setRequestParam('request_param_foo');
    $_POST['request_param_foo'] = 'qux';
    assert($csrf->findToken() === 'qux');
    unset($_POST['request_param_foo']);
});

test("Csrf::formInput() and Csrf::metaTag() return well-formatted HTML5 tags.", function () {
    $csrf = new \kafene\Csrf();

    $hash = $csrf->getToken();
    $formInput = $csrf->formInput();
    $metaTag = $csrf->metaTag();

    assert('<input type="hidden" name="csrf_token" value="' . $hash . '">' === $formInput);
    assert('<meta name="X-Csrf-Token" content="' . $hash . '">' === $metaTag);
});

test("Csrf::createNonce() does not return the same value twice.", function () {
    $csrf = new \kafene\Csrf();
    $createNonce = new \ReflectionMethod($csrf, 'createNonce');
    $createNonce->setAccessible(true);

    $nonce1 = $createNonce->invoke($csrf);
    $nonce2 = $createNonce->invoke($csrf);

    assert($nonce1 !== $nonce2);
});

test("Csrf::createNonce() respects the `bytes` argument.", function () {
    $csrf = new \kafene\Csrf();
    $createNonce = new \ReflectionMethod($csrf, 'createNonce');
    $createNonce->setAccessible(true);

    $nonce1 = $createNonce->invoke($csrf, 32);
    $nonce2 = $createNonce->invoke($csrf, 40);

    $nonce1 = base64_decode($nonce1);
    $nonce2 = base64_decode($nonce2);

    assert(32 === mb_strlen($nonce1, '8bit'));
    assert(40 === mb_strlen($nonce2, '8bit'));
});

test("Csrf::getUserData() returns the correct user data.", function () {
    $csrf = new \kafene\Csrf();

    $hashAlgorithm = $csrf->getHashAlgorithm();

    $getUserData = new \ReflectionMethod($csrf, 'getUserData');
    $getUserData->setAccessible(true);

    $_SERVER['REMOTE_ADDR'] = '127.0.0.5';
    $_SERVER['HTTP_USER_AGENT'] = 'Mozzarella Foxfire';

    $testData = hash($hashAlgorithm, serialize(array(
        $_SERVER['REMOTE_ADDR'],
        $_SERVER['HTTP_USER_AGENT']
    )));

    $userData = $getUserData->invoke($csrf);
    assert($userData === $testData);

    unset($_SERVER['HTTP_USER_AGENT']);

    $testData = hash($hashAlgorithm, serialize(array(
        $_SERVER['REMOTE_ADDR']
    )));

    $userData = $getUserData->invoke($csrf);
    assert($userData === $testData);
});

test();

// a little test helper
function test($description = null, callable $callback = null) {
    static $firstRun = true;
    static $testsPassed = 0;
    static $testsFailed = 0;
    static $testCallbacks = [];

    if ($firstRun) {
        $firstRun = false;
        assert_options(ASSERT_ACTIVE, true);
        assert_options(ASSERT_WARNING, true);
        assert_options(ASSERT_BAIL, false);

        set_error_handler(function ($errno, $errstr, $errfile, $errline) {
            throw new \ErrorException($errstr, $errno, 0, $errfile, $errline);
        });

        print "<h1>kafene\\Csrf Test Results:</h1><hr>";
    }

    if (0 === func_num_args()) {
        foreach ($testCallbacks as $description => $testCallback) {
            try {
                $testCallback();
                $testsPassed += 1;
                print '<p>'
                    . '<strong>Test passed:</strong> '
                    . $description
                    . '</p>';
            } catch (\Exception $e) {
                $testsFailed += 1;
                print '<p>'
                    . '<strong style="color:red;">Test failed:</strong> '
                    . $description
                    . '</p>'
                    . '<pre>'
                    . '[Line ' . $e->getLine() . ']: '
                    . $e->getMessage()
                    . '</pre>';
            }
        }

        $total = $testsPassed + $testsFailed;

        print '<hr>'
            . '<strong>Summary:</strong>'
            . '<br>'
            . 'Passed: '
            . $testsPassed . '/' . $total
            . ' <br> '
            . 'Failed: '
            . $testsFailed . '/' . $total
            . '<hr>';
    } else {
        $testCallbacks[$description] = $callback;
    }
}
