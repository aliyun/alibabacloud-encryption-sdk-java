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

package com.aliyun.encryptionsdk.model.test;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.kms.AliyunKms;
import com.aliyun.encryptionsdk.kms.DefaultAliyunKms;
import com.aliyun.encryptionsdk.model.CmkId;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.model.EncryptedDataKey;
import com.aliyun.encryptionsdk.TestAccount;
import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class EncryptedDataKeyTest {
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final AliyunConfig CONFIG = TestAccount.AliyunKMS.getAliyunConfig();

    @Test
    public void test(){
        AliyunCrypto crypto = new AliyunCrypto(CONFIG);
        CryptoAlgorithm algorithm = CryptoAlgorithm.AES_GCM_NOPADDING_256;
        DefaultAliyunKms aliyunKms = new DefaultAliyunKms(CONFIG);
        AliyunKms.GenerateDataKeyResult generateDataKeyResult =
                aliyunKms.generateDataKey(new CmkId(KEY_ID), algorithm, Collections.singletonMap("test", "generate"));
        String plaintext = generateDataKeyResult.getPlaintext();
        EncryptedDataKey encryptedDataKey = aliyunKms.encryptDataKey(new CmkId(KEY_ID), plaintext, Collections.singletonMap("test", "generate"));
        AliyunKms.DecryptDataKeyResult decryptDataKeyResult = aliyunKms.decryptDataKey(encryptedDataKey, Collections.singletonMap("test", "generate"));
        assertEquals(plaintext, decryptDataKeyResult.getPlaintext());
    }
}
