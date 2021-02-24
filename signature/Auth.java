package com.realsee;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.CRC32;

public class Auth {

    private static final BASE64Encoder base64Encoder = new BASE64Encoder();

    /**
     * note:
     * the param uri must start with character '/'.
     * the param timestamp is in seconds.
     * the param requestMethod is HTTP method like 'GET','POST'
     *
     * @param uri           the request uri
     * @param timestamp     the time of request action
     * @param params        request param
     * @param requestMethod request method
     * @param appId         your appID from RealSee
     * @param appSecret     your appSecret from RealSee
     * @return
     * @throws Exception
     */
    public static String encrypt(String uri, long timestamp, Map<String, Object> params,
                                 String requestMethod, String appId, String appSecret) throws Exception {
        if (isEmpty(uri) || isEmpty(requestMethod) || isEmpty(appId) || isEmpty(appSecret)) {
            throw new IllegalArgumentException("uri, requestMethod, appId, appSecret cannot be empty string");
        }
        if (params == null) {
            throw new IllegalArgumentException("params cannot be null");
        }

        // sort param by key，and coding with URLEncode for the param value
        params = buildSortParam(params);
        for (Map.Entry<String, Object> stringObjectEntry : params.entrySet()) {
            params.put(stringObjectEntry.getKey(),
                    stringObjectEntry.getValue() == null
                            ? "null"
                            : URLEncoder.encode(stringObjectEntry.getValue().toString(), "UTF-8"));
        }

        // coding param to String and linked with a '&'
        String paramKey = params.entrySet().stream()
                .map(o -> o.getKey() + "=" + o.getValue() + "&")
                .reduce("", (a, b) -> a + b);
        if (paramKey.length() > 1) {
            paramKey = paramKey.substring(0, paramKey.length() - 1);
        }

        // coding paramKey with CRC32
        CRC32 crc32 = new CRC32();
        crc32.update(paramKey.getBytes());
        String bodyCrc32 = String.valueOf(crc32.getValue());

        // build stringToSign
        Map<String, Object> encryptMap = new LinkedHashMap<>();
        encryptMap.put("body_crc32", bodyCrc32);
        encryptMap.put("method", requestMethod.toUpperCase());
        encryptMap.put("url", uri);
        String stringToSign = encryptMap.entrySet().stream()
                .map(o -> o.getKey() + "=" + (o.getValue() == null ? "null" : o.getValue().toString()))
                .reduce("", (a, b) -> a + b);

        // build salt
        String salt = StringUtils.upperCase(DigestUtils.md5Hex((appId + appSecret + timestamp).getBytes()));

        // generate signature
        String signature = HMACSHA256(stringToSign, salt);

        return base64Encoder.encode((appId + ":" + signature + ":" + timestamp).getBytes()).replaceAll("\r|\n", "");
    }

    private static LinkedHashMap<String, Object> buildSortParam(Map<String, Object> params) {
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();

        params.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(o -> {
            result.put(o.getKey(), o.getValue());
        });

        return result;
    }

    private static String HMACSHA256(String data, String key) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] array = sha256_HMAC.doFinal(data.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte item : array) {
            sb.append(Integer.toHexString((item & 0xFF) | 0x100).substring(1, 3));
        }
        return sb.toString().toUpperCase();
    }

    private static boolean isEmpty(String str) {
        return str == null || "".equals(str);
    }
}
