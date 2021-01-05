<?php

/**
 * Method  calculateSignature
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
function calculateSignature(string $appId, string $appSecret, string $http_method, string $http_uri, array $params = [])
{
    $timestamp = time(); // now

    $params = [
        'method' => strtoupper($http_method),
        'url'    => $http_uri,
    ];

    if (!empty($params)) {
        ksort($params);
        $params['body_crc32'] = crc32(http_build_query($params));
    }

    ksort($params);

    $signatureElements = [];

    foreach ($params as $key => $value) {
        $signatureElements[] = "{$key}={$value}";
    }

    // hash_hmac即sha256
    return strtoupper(hash_hmac('sha256', implode('', $signatureElements), strtoupper(md5($appId . $appSecret . $timestamp))));
}
