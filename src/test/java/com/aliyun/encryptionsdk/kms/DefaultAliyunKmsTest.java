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

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.TestAccount;
import org.junit.Before;
import org.junit.Test;

import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.aliyun.encryptionsdk.AliyunCryptoTest.hex2Bytes;
import static org.junit.Assert.*;

public class DefaultAliyunKmsTest {
    private static CmkId cmkId;
    private static final String RSA2048_KEY_ID = "acs:kms:cn-hangzhou:1540355698848459:key/4358f298-8e30-4849-9791-52e68dbd9d1e";
    private static final String RSA2048_KEY_VERSION_ID = "e71daa69-c321-4014-b0c4-ba070c7839ee";
    private static final String AES256_KEY_ID = "acs:kms:cn-hangzhou:1540355698848459:key/8f4e7312-b204-4f6b-b473-447fe038f1b9";
    private static final String AES256_KEY_VERSION_ID = "82628348-c73a-4451-a9a2-d37d4a6497ef";
    private static final String SM2_KEY_ID = "acs:kms:cn-hangzhou:1540355698848459:key/1f777304-404b-4278-a56e-4343f20534fd";
    private static final String SM2_KEY_VERSION_ID = "9104b2a9-f602-403e-8c63-767cebd2044d";
    private static CryptoAlgorithm algorithm;
    private static Map<String, String> encryptionContext;
    private static AliyunConfig config;
    private static DefaultAliyunKms aliyunKms;
    @Before
    public void setUp(){
        encryptionContext = new HashMap<>();
        encryptionContext.put("default", "context");
        encryptionContext.put("simple", "test");
        encryptionContext.put("aliyun", "kms");

        config = TestAccount.AliyunKMS.getAliyunConfig();
        aliyunKms = new DefaultAliyunKms(config);
        AliyunCrypto crypto = new AliyunCrypto(config);
    }

    @Test
    public void testGenerateDataKey(){
        cmkId = new CmkId(AES256_KEY_ID);
        algorithm = CryptoAlgorithm.AES_GCM_NOPADDING_256;
        DefaultAliyunKms aliyunKms = new DefaultAliyunKms(config);
        AliyunKms.GenerateDataKeyResult generateDataKeyResult = aliyunKms.generateDataKey(cmkId, algorithm, encryptionContext);
        assertNotNull(generateDataKeyResult.getPlaintext());
        assertEquals(cmkId.getKeyId(), generateDataKeyResult.getKeyId());
        assertEquals(AES256_KEY_VERSION_ID, generateDataKeyResult.getKeyVersionId());
    }

    @Test
    public void testEncryptDecryptDataKey(){
        cmkId = new CmkId(AES256_KEY_ID);
        algorithm = CryptoAlgorithm.AES_GCM_NOPADDING_256;
        AliyunKms.GenerateDataKeyResult generateDataKeyResult = aliyunKms.generateDataKey(cmkId, algorithm, encryptionContext);
        String plaintext = generateDataKeyResult.getPlaintext();
        EncryptedDataKey encryptedDataKey = aliyunKms.encryptDataKey(cmkId, plaintext, encryptionContext);
        AliyunKms.DecryptDataKeyResult decryptDataKeyResult = aliyunKms.decryptDataKey(encryptedDataKey, Collections.EMPTY_MAP);
        assertEquals(plaintext, decryptDataKeyResult.getPlaintext());
    }

    @Test
    public void testAsymmetricSignVerify(){
        cmkId = new CmkId(RSA2048_KEY_ID);
        byte[] sha256Digest = hex2Bytes("FECC75FE2A23D8EAFBA452EE0B8B6B56BECCF52278BF1398AADDEECFE0EA0FCE");
        AliyunKms.AsymmetricSignResult asymmetricSignResult =
                aliyunKms.asymmetricSign(cmkId, RSA2048_KEY_VERSION_ID, SignatureAlgorithm.RSA_PKCS1_SHA_256, sha256Digest);
        String value = asymmetricSignResult.getValue();
        AliyunKms.AsymmetricVerifyResult asymmetricVerifyResult =
                aliyunKms.asymmetricVerify(cmkId, RSA2048_KEY_VERSION_ID, SignatureAlgorithm.RSA_PKCS1_SHA_256, sha256Digest, Base64.getDecoder().decode(value));
        assertTrue(asymmetricVerifyResult.getValue());
    }

    @Test
    public void testCreateSecretAndGetSecretValue(){
        cmkId = new CmkId(AES256_KEY_ID);
        String secretData = "{\"user\":\"root\",\"passwd\":\"****\"}";
        AliyunKms.CreateSecretResult secret = aliyunKms.createSecret(cmkId, "testSecretName", AES256_KEY_VERSION_ID, secretData, "text");
        assertEquals("testSecretName", secret.getSecretName());
        AliyunKms.GetSecretValueResult secretValue = aliyunKms.getSecretValue(cmkId, "testSecretName");
        assertEquals("testSecretName", secretValue.getSecretName());
        assertEquals("text", secretValue.getSecretDataType());
        assertEquals(secretData, secretValue.getSecretData());
    }

    @Test
    public void testGetPublicKey() throws Exception {
        cmkId = new CmkId(SM2_KEY_ID);
        String publicKey = aliyunKms.getPublicKey(cmkId, SM2_KEY_VERSION_ID);
        assertNotNull(publicKey);
    }
}
