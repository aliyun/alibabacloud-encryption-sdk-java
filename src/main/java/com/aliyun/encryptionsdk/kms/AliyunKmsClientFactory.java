/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aliyun.encryptionsdk.kms;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import java.util.Properties;

public class AliyunKmsClientFactory {

    public static IAcsClient getClient(AliyunConfig config, String region) {
        return createKmsClient(config, region);
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
        try{
            props.load(AliyunKmsClientFactory.class.getClassLoader().getResourceAsStream("encsdk.properties"));
            String encsdkVersion = props.getProperty("encsdk.project.version");
            return encsdkVersion;
        }catch(Exception e){
            e.printStackTrace();
        }
        return "";
    }
}
