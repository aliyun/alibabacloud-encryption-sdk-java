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

import com.aliyun.dkms.gcs.openapi.models.Config;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunKmsConfig;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.TestAccount;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static com.aliyun.encryptionsdk.AliyunCryptoTest.hex2Bytes;
import static org.junit.Assert.*;

public class DefaultAliyunKmsTest {
    private static CmkId cmkId;
    private static final String RSA2048_KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String RSA2048_KEY_VERSION_ID = "versionId";
    private static final String AES256_KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String AES256_KEY_VERSION_ID = "versionId";
    private static final String SM2_KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String SM2_KEY_VERSION_ID = "versionId";
    private static CryptoAlgorithm algorithm;
    private static Map<String, String> encryptionContext;
    private static AliyunConfig config;
    private AliyunKmsConfig aliyunKmsConfig;
    private static DefaultAliyunKms aliyunKms;
    @Before
    public void setUp(){
        CommonLogger.registerLogger(Constants.MODE_NAME, LoggerFactory.getLogger(Constants.MODE_NAME));
        encryptionContext = new HashMap<>();
        encryptionContext.put("default", "context");
        encryptionContext.put("simple", "test");
        encryptionContext.put("aliyun", "kms");
        InputStream stream = TestAccount.class.getResourceAsStream("/fixture/dkmsConfig.json");
        Map<String, String> result = new Gson().fromJson(new InputStreamReader(stream), new TypeToken<Map<String, String>>() {}.getType());
        this.aliyunKmsConfig = new AliyunKmsConfig();
        this.aliyunKmsConfig.withAccessKey(result.get("accessKeyId"),result.get("accessKeySecret"));
        Config config = new Config();
        config.setRegionId(result.get("regionId"));
        config.setClientKeyFile(result.get("clientKeyFile"));
        config.setPassword(result.get("password"));
        config.setEndpoint(result.get("endpoint"));
        config.setProtocol(result.get("protocol"));
        this.aliyunKmsConfig.addDkmsConfig(new DkmsConfig(config,true));
//        this.aliyunCrypto = new AliyunCrypto(aliyunDkmsConfig);
//        config = TestAccount.AliyunKMS.getAliyunConfig();
        aliyunKms = new DefaultAliyunKms(this.aliyunKmsConfig);
//        AliyunCrypto crypto = new AliyunCrypto(config);
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
        AliyunKms.DecryptDataKeyResult decryptDataKeyResult = aliyunKms.decryptDataKey(encryptedDataKey, encryptionContext);
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
