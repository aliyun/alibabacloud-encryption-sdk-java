package com.aliyun.encryptionsdk.utils;

import com.aliyuncs.utils.StringUtils;

public class EndpointUtils {

    public static String resolveDKMSInstanceId(String endpoint) {
        if (!StringUtils.isEmpty(endpoint)) {
            return endpoint.split("\\.")[0];
        }
        return null;
    }
}
