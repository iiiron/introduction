<?php

/**
 * Method  getAuthorization
 *
 * @author realsee-developers
 *
 * @param string $appId
 * @param string $appSecret
 * @param string $http_method HTTP method: GET/POST
 * @param string $http_uri    HTTP URI
 * @param array  $params      GET query strings/POST body
 *
 * @return string
 */
function getAuthorization(string $appId, string $appSecret, string $http_method, string $http_uri, array $params = [], bool $debug)
{
    // 1. Sort
    ksort($params);

    // 2. Get current timestamp
    $timestamp = time(); // now

    $paramsForSign = [];
    foreach ($params as $key => $value) {
        $paramsForSign[] = "{$key}={$value}";
    }

    $arrayForSign = [
        'body_crc32' => crc32(http_build_query($paramsForSign)),
        'method' => strtoupper($http_method),
        'url'    => $http_uri,
    ];
    $stringForSign = implode('', $arrayForSign);

    $salt = strtoupper(md5($appId . $appSecret . $timestamp));

    $signature = strtoupper(hash_hmac('sha256', $stringForSign, $salt));

    $stringForAuth =  $appId . ':' . $signature . ':' . $timestamp;
    $authorization = base64_encode($stringForAuth);

    if ($debug) {
        echo '__DEBUG__' . PHP_EOL;
        var_dump('paramsForSign', $paramsForSign, 'stringForSign', $stringForSign, 'stringForAuth', $stringForAuth);
        var_dump('original', $appId . $appSecret . $timestamp, 'salt', $salt, 'signature', $signature, 'authorization', $authorization);
        echo '__DEBUG__' . PHP_EOL;
    }

    // hash_hmac即sha256
    return $authorization;
}


echo getAuthorization('1017', 'hello world', 'POST', '/a/b/c.json', ['foo' => 'bar'], false);
