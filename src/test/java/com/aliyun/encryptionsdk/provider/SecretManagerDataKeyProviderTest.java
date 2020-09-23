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

package com.aliyun.encryptionsdk.provider;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.provider.dataKey.SecretManagerDataKeyProvider;
import com.aliyun.encryptionsdk.TestAccount;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;

public class SecretManagerDataKeyProviderTest {
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final AliyunConfig CONFIG = TestAccount.AliyunKMS.getAliyunConfig();
    private static final AliyunCrypto ALIYUN_CRYPTO = new AliyunCrypto(CONFIG);

    @Test
    public void testBuildAndUseful(){
        String plaintext = "this is test.";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("adds", "useful metadata");

        String dataKeyId = "dataKeyName";

        BaseDataKeyProvider secretManagerDataKeyProvider = new SecretManagerDataKeyProvider(KEY_ID, dataKeyId);

        byte[] encryptResult = ALIYUN_CRYPTO.encrypt(secretManagerDataKeyProvider, plaintext.getBytes(), encryptionContext).getResult();
        byte[] decryptResult = ALIYUN_CRYPTO.decrypt(secretManagerDataKeyProvider, encryptResult).getResult();

        assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decryptResult);
    }
}
