/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aliyun.encryptionsdk.kms;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunKmsConfig;
import com.aliyun.encryptionsdk.model.CmkId;
import com.aliyun.encryptionsdk.model.Constants;
import com.aliyun.encryptionsdk.model.DkmsConfig;
import com.aliyun.kms.KmsTransferAcsClient;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.aliyuncs.utils.StringUtils;

import java.util.Map;
import java.util.Properties;

public class AliyunKmsClientFactory {

    public static IAcsClient getClient(AliyunConfig config, String region) {
        return createKmsClient(config, region);
    }

    public static DefaultAcsClient getDKmsClient(AliyunKmsConfig aliyunKmsConfig, CmkId cmkId) {
        if (!StringUtils.isEmpty(cmkId.getInstanceId())) {
            return AliyunKmsClientFactory.createDKmsClient(aliyunKmsConfig, cmkId);
        }
        if (cmkId.getKmsType() == null || Constants.KMS_TYPE_KMS != cmkId.getKmsType()) {
            cmkId.refreshMetadata(AliyunKmsClientFactory.getClient(aliyunKmsConfig, cmkId.getRegion()));
            if (!StringUtils.isEmpty(cmkId.getInstanceId())) {
                return AliyunKmsClientFactory.createDKmsClient(aliyunKmsConfig, cmkId);
            }
        }
        return null;
    }

    public static DefaultAcsClient createDKmsClient(AliyunKmsConfig aliyunKmsConfig, CmkId cmkId) {
        Map<String, DkmsConfig> dkmsConfigMap = aliyunKmsConfig.getDkmsConfigMap();
        if (dkmsConfigMap.isEmpty()) {
            throw new IllegalArgumentException("DkmsConfig can not be null");
        }
        DkmsConfig dkmsConfig = dkmsConfigMap.get(cmkId.getInstanceId());
        if (dkmsConfig == null) {
            throw new IllegalArgumentException(String.format("InstanceId: %s of DkmsConfig can not be null", cmkId.getInstanceId()));
        }
        IClientProfile profile = DefaultProfile.getProfile(cmkId.getRegion());
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        clientConfig.setIgnoreSSLCerts(dkmsConfig.getIgnoreSslCerts());
        profile.setHttpClientConfig(clientConfig);
        return new KmsTransferAcsClient(profile, aliyunKmsConfig.getProvider(), dkmsConfig.getConfig());
    }

    private static DefaultAcsClient createKmsClient(AliyunConfig config, String region) {
        IClientProfile profile = DefaultProfile.getProfile(region);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        profile.setHttpClientConfig(clientConfig);
        DefaultAcsClient client = new DefaultAcsClient(profile, config.getProvider());
        client.appendUserAgent("AliyunEncSDK-java", getProjectVersion());
        return client;
    }

    private static String getProjectVersion() {
        Properties props = new Properties();
        try {
            props.load(AliyunKmsClientFactory.class.getClassLoader().getResourceAsStream("encsdk.properties"));
            String encsdkVersion = props.getProperty("encsdk.project.version");
            return encsdkVersion;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

}
