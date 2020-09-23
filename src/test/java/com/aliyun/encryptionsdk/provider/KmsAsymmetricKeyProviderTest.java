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
import com.aliyun.encryptionsdk.model.SignatureAlgorithm;
import com.aliyun.encryptionsdk.model.ContentType;
import com.aliyun.encryptionsdk.TestAccount;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class KmsAsymmetricKeyProviderTest {
    private static final AliyunConfig CONFIG = TestAccount.AliyunKMS.getAliyunConfig();
    private static final AliyunCrypto ALIYUN_CRYPTO = new AliyunCrypto(CONFIG);
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String KEY_VERSION_ID = "keyVersionId";

    @Test
    public void testBuildAndUseful(){
        // RSA非对称密钥签名验签，keySpec=RSA_2048，keyUsage=SIGN/VERIFY
        SignatureProvider provider = new KmsAsymmetricKeyProvider(KEY_ID, KEY_VERSION_ID, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        byte[] msg = "this is test.".getBytes();

        // 使用原始消息
        byte[] signature = ALIYUN_CRYPTO.sign(provider, msg, ContentType.MESSAGE).getResult();
        Boolean isOk = ALIYUN_CRYPTO.verify(provider, msg, signature, ContentType.MESSAGE).getResult();
        assertTrue(isOk);
    }
}
