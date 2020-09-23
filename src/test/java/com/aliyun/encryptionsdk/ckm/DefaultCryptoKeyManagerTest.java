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

package com.aliyun.encryptionsdk.ckm;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.kms.DefaultAliyunKms;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import com.aliyun.encryptionsdk.provider.KmsAsymmetricKeyProvider;
import com.aliyun.encryptionsdk.TestAccount;
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.Before;
import org.junit.Test;

import java.util.*;

import static com.aliyun.encryptionsdk.AliyunCryptoTest.hex2Bytes;
import static org.junit.Assert.*;


public class DefaultCryptoKeyManagerTest {
    private static Map<String, String> encryptionContext;
    private static final String DEFAULT_KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String PLAIN_TEXT = "this is test.";
    private static BaseDataKeyProvider dataKeyProvider;
    private static AliyunCrypto defaultAliyunCrypto;
    private AliyunConfig config;

    @Before
    public void setUp() {
        encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("simple", "test");
        encryptionContext.put("default", "ckm");

        config = TestAccount.AliyunKMS.getAliyunConfig();

        dataKeyProvider = new DefaultDataKeyProvider(DEFAULT_KEY_ID);

        defaultAliyunCrypto = new AliyunCrypto(config);
    }

    @Test
    public void encrypt_testBasicFunctionality() {
        EncryptionMaterial result = new DefaultCryptoKeyManager().getEncryptDataKeyMaterial(TestFixtures.createDefaultDataKeyProvider(), encryptionContext, 1);

        assertNotNull(result.getAlgorithm());
        assertNotNull(result.getPlaintextDataKey());
        assertNotNull(result.getEncryptionContext());
        assertEquals(1, result.getEncryptedDataKeys().size());
    }

    @Test
    public void decrypt_testBasicFunctionality() {
        EncryptionMaterial encryptionMaterial = TestFixtures.createMaterialsResult(1);
        DecryptionMaterial result = new DefaultCryptoKeyManager().getDecryptDataKeyMaterial(TestFixtures.createDefaultDataKeyProvider(),
                encryptionMaterial.getEncryptionContext(), encryptionMaterial.getEncryptedDataKeys());
        assertNotNull(result.getAlgorithm());
        assertNotNull(result.getPlaintextDataKey());
        assertNotNull(result.getEncryptionContext());
    }

    @Test(expected = UnFoundDataKeyException.class)
    public void decrypt_testDataKeyUnFound() {
        new DefaultCryptoKeyManager().getDecryptDataKeyMaterial(dataKeyProvider, Collections.emptyMap(), Collections.singletonList(new EncryptedDataKey(DEFAULT_KEY_ID, DEFAULT_KEY_ID)));
    }

    @Test
    public void sign_testBasicFunctionality() {
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String keyVersionId = "keyVersionId";
        SignatureProvider keyProvider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        keyProvider.setAliyunKms(new DefaultAliyunKms(config));

        SignatureMaterial message = new DefaultCryptoKeyManager().getSignatureMaterial(keyProvider, PLAIN_TEXT.getBytes(), ContentType.MESSAGE);
        assertArrayEquals(PLAIN_TEXT.getBytes(), message.getMessage());
        assertEquals(SignatureAlgorithm.RSA_PKCS1_SHA_256, message.getSignatureAlgorithm());
        assertEquals(new CmkId(keyId).getRawKeyId(), message.getKeyId());
        assertEquals(keyVersionId, message.getKeyVersionId());
    }

    @Test
    public void verify_testBasicFunctionality() {
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String keyVersionId = "keyVersionId";
        byte[] sha256Digest = hex2Bytes("FECC75FE2A23D8EAFBA452EE0B8B6B56BECCF52278BF1398AADDEECFE0EA0FCE");
        SignatureProvider keyProvider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        byte[] signature = defaultAliyunCrypto.sign(keyProvider, sha256Digest, ContentType.DIGEST).getResult();
        VerifyMaterial result = new DefaultCryptoKeyManager().getVerifyMaterial(keyProvider, sha256Digest, signature, ContentType.DIGEST);
        assertTrue(result.getValue());
        assertEquals(signature, result.getSignature());
        assertEquals(SignatureAlgorithm.RSA_PKCS1_SHA_256, result.getSignatureAlgorithm());
        assertEquals(new CmkId(keyId).getRawKeyId(), result.getKeyId());
        assertEquals(keyVersionId, result.getKeyVersionId());
        assertEquals(sha256Digest, result.getDigest());
    }
}
