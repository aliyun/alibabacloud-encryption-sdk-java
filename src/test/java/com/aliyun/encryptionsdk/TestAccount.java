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

package com.aliyun.encryptionsdk;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class TestAccount {
    /**
     * 从文件中读取阿里云AccessKey配置信息
     * 此处为了单元测试执行的环境普适性，AccessKey信息配置在resources资源下，实际过程中请不要这样做。
     *
     * @param key AccessKey配置对应的key
     * @return AccessKey配置字符串
     */
    private static String getAliyunAccessKey(String key) {
        InputStream stream = TestAccount.class.getResourceAsStream("/fixture/aliyunAccessKey.json");
        Map<String, String> result = new Gson().fromJson(new InputStreamReader(stream), new TypeToken<Map<String, String>>() {}.getType());
        return result.get(key);
    }

    public static class AliyunKMS {
        public static final String ACCESS_KEY_ID = getAliyunAccessKey("AccessKeyId");

        public static final String ACCESS_KEY_SECRET = getAliyunAccessKey("AccessKeySecret");

        public static final String KMS_REGION_ID = "cn-hangzhou";

        public static final AliyunConfig ENCRYPTION_CONFIG = getAliyunConfig();

        public static AliyunConfig getAliyunConfig() {
            AliyunConfig config = new AliyunConfig();
            config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
//          config.withRamRoleArnOrSts(ACCESS_KEY_ID, ACCESS_KEY_SECRET, KMS_REGION_ID, "test", "", null)
//          config.withEcsRamRole("")
            return config;
        }
    }
}
