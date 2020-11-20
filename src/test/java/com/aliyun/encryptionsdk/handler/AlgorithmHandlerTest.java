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

package com.aliyun.encryptionsdk.handler;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.ckm.DefaultCryptoKeyManager;
import com.aliyun.encryptionsdk.kms.DefaultAliyunKms;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.model.EncryptionMaterial;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import com.aliyun.encryptionsdk.TestAccount;
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.Test;

import javax.crypto.Cipher;
import java.security.SecureRandom;
import java.util.Collections;

import static org.junit.Assert.assertArrayEquals;

public class AlgorithmHandlerTest {

    private static final String PLAIN_TEXT = "this is test.";
    private static final CryptoAlgorithm DEFAULT_ALGORITHM = CryptoAlgorithm.AES_GCM_NOPADDING_256;
    private static final AliyunConfig CONFIG = TestAccount.AliyunKMS.getAliyunConfig();
    private static final String SM4_KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";

    @Test
    public void testEncryptDecrypt() {
        EncryptionMaterial encryptDataKeyMaterial = new DefaultCryptoKeyManager().getEncryptDataKeyMaterial(TestFixtures.createDefaultDataKeyProvider(),
                Collections.singletonMap("index", "1"), 1);
        AlgorithmHandler handler = new AlgorithmHandler(DEFAULT_ALGORITHM, encryptDataKeyMaterial.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        byte[] iv = new byte[encryptDataKeyMaterial.getAlgorithm().getIvLen()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        byte[] contentAad = null;
        if (encryptDataKeyMaterial.getAlgorithm().isWithAad()) {
            contentAad = TestFixtures.serializeContext(encryptDataKeyMaterial.getEncryptionContext());
        }
        byte[] encryptedResult = handler.cipherData(iv, contentAad, PLAIN_TEXT.getBytes(), 0, PLAIN_TEXT.length());
        handler = new AlgorithmHandler(DEFAULT_ALGORITHM, encryptDataKeyMaterial.getPlaintextDataKey(), Cipher.DECRYPT_MODE);
        byte[] decryptedResult = handler.cipherData(iv, contentAad, encryptedResult, 0, encryptedResult.length);
        assertArrayEquals(PLAIN_TEXT.getBytes(), decryptedResult);
    }

    @Test
    public void testSM4EncryptDecrypt() {
        AliyunCrypto aliyunCrypto = new AliyunCrypto(CONFIG);
        CryptoAlgorithm algorithm = CryptoAlgorithm.SM4_GCM_NOPADDING_128;
        BaseDataKeyProvider provider = sm4DataKeyProvider();
        provider.setAlgorithm(createSM4Algorithm());
        EncryptionMaterial encryptDataKeyMaterial = new DefaultCryptoKeyManager().getEncryptDataKeyMaterial(provider, Collections.singletonMap("index", "1"), 1);
        AlgorithmHandler handler = new AlgorithmHandler(algorithm, encryptDataKeyMaterial.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        byte[] iv = new byte[encryptDataKeyMaterial.getAlgorithm().getIvLen()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        byte[] contentAad = null;
        if (encryptDataKeyMaterial.getAlgorithm().isWithAad()) {
            contentAad = TestFixtures.serializeContext(encryptDataKeyMaterial.getEncryptionContext());
        }
        byte[] encryptedResult = handler.cipherData(iv, contentAad, PLAIN_TEXT.getBytes(), 0, PLAIN_TEXT.length());
        handler = new AlgorithmHandler(createSM4Algorithm(), encryptDataKeyMaterial.getPlaintextDataKey(), Cipher.DECRYPT_MODE);
        byte[] decryptedResult = handler.cipherData(iv, contentAad, encryptedResult, 0, encryptedResult.length);
        assertArrayEquals(PLAIN_TEXT.getBytes(), decryptedResult);
    }

    private static CryptoAlgorithm createSM4Algorithm() {
        return CryptoAlgorithm.SM4_GCM_NOPADDING_128;
    }

    private static BaseDataKeyProvider sm4DataKeyProvider() {
        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(SM4_KEY_ID);
        dataKeyProvider.setAliyunKms(new DefaultAliyunKms(CONFIG));
        return dataKeyProvider;
    }
}
