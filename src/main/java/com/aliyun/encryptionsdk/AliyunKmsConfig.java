package com.aliyun.encryptionsdk;

import com.aliyun.dkms.gcs.openapi.models.Config;
import com.aliyun.encryptionsdk.model.DkmsConfig;
import com.aliyun.encryptionsdk.utils.EndpointUtils;
import com.aliyuncs.utils.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class AliyunKmsConfig extends AliyunConfig {

    private Map<String, DkmsConfig> dkmsConfigMap = new HashMap<>();

    public Map<String, DkmsConfig> getDkmsConfigMap() {
        return dkmsConfigMap;
    }

    public void addConfig(Config config) {
        this.addDkmsConfig(new DkmsConfig(config));
    }

    public void addDkmsConfig(DkmsConfig dkmsConfig) {
        checkParam(dkmsConfig);
        this.dkmsConfigMap.put(EndpointUtils.resolveDKMSInstanceId(dkmsConfig.getConfig().getEndpoint()), dkmsConfig);
    }

    private void checkParam(DkmsConfig dkmsConfig) {
        Config config = dkmsConfig.getConfig();
        if (config == null) {
            throw new IllegalArgumentException("DkmsConfig property[config] can not be null");
        }
        if (StringUtils.isEmpty(config.getEndpoint())) {
            throw new IllegalArgumentException("DkmsConfig.config property[endpoint] can not be null");
        }
    }
}
