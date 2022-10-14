package com.aliyun.encryptionsdk.model;

import com.aliyun.dkms.gcs.openapi.models.Config;

public class DkmsConfig {

    private Config config;
    private boolean ignoreSslCerts;

    public DkmsConfig(Config config) {
        this.config = config;
    }

    public DkmsConfig(Config config, boolean ignoreSslCerts) {
        this.config = config;
        this.ignoreSslCerts = ignoreSslCerts;
    }

    public Config getConfig() {
        return config;
    }

    public boolean getIgnoreSslCerts() {
        return ignoreSslCerts;
    }

}
