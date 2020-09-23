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

import com.aliyun.encryptionsdk.ckm.DefaultCryptoKeyManager;
import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.kms.DefaultAliyunKms;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TestFixtures {
    public static final AliyunCrypto ALIYUN_CRYPTO = new AliyunCrypto(TestAccount.AliyunKMS.getAliyunConfig());
    public static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";

    public static EncryptionMaterial createMaterialsResult(int index) {
        BaseDataKeyProvider provider = createDefaultDataKeyProvider();
        return new DefaultCryptoKeyManager().getEncryptDataKeyMaterial(provider, Collections.singletonMap("index", Integer.toString(index)), 1);
    }

    public static DecryptionMaterial createDecryptResult(int index) {
        EncryptionMaterial material = createMaterialsResult(index);
        BaseDataKeyProvider provider = createDefaultDataKeyProvider();
        return new DefaultCryptoKeyManager().getDecryptDataKeyMaterial(provider, material.getEncryptionContext(), material.getEncryptedDataKeys());
    }

    public static BaseDataKeyProvider createDefaultDataKeyProvider() {
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(KEY_ID);
        provider.setAliyunKms(new DefaultAliyunKms(TestAccount.AliyunKMS.getAliyunConfig()));
        return provider;
    }

    public static void assertCipherMaterialEquals(CipherMaterial cipherMaterial, CipherMaterial actualCipherMaterial) {
        assertCipherBodyEquals(cipherMaterial.getCipherBody(), actualCipherMaterial.getCipherBody());
        assertCipherHeaderEquals(cipherMaterial.getCipherHeader(), actualCipherMaterial.getCipherHeader());

    }

    public static void assertCipherHeaderEquals(CipherHeader cipherHeader, CipherHeader actualCipherHeader) {
        assertEncryptionContextEquals(cipherHeader.getEncryptionContext(), actualCipherHeader.getEncryptionContext());
        assertEncryptionAlgorithmEquals(cipherHeader.getAlgorithm(), actualCipherHeader.getAlgorithm());
        assertEncryptedDataKeysEquals(cipherHeader.getEncryptedDataKeys(), actualCipherHeader.getEncryptedDataKeys());
    }

    public static void assertEncryptedDataKeysEquals(List<EncryptedDataKey> encryptedDataKeys, List<EncryptedDataKey> encryptedDataKeys1) {
        assertEquals(encryptedDataKeys.size(),encryptedDataKeys1.size());
        for (int i = 0; i < encryptedDataKeys.size(); i++) {
            assertEncryptDataKeyEquals(encryptedDataKeys.get(i), encryptedDataKeys1.get(i));
        }
    }

    public static void assertEncryptDataKeyEquals(EncryptedDataKey encryptedDataKey, EncryptedDataKey encryptedDataKey1) {
        assertArrayEquals(encryptedDataKey.getDataKey(), encryptedDataKey1.getDataKey());
        assertArrayEquals(encryptedDataKey.getKeyId(), encryptedDataKey1.getKeyId());
        assertEquals(encryptedDataKey.getDataKeyString(), encryptedDataKey1.getDataKeyString());
        assertEquals(encryptedDataKey.getKeyIdString(), encryptedDataKey1.getKeyIdString());
    }

    public static void assertEncryptionAlgorithmEquals(CryptoAlgorithm algorithm, CryptoAlgorithm algorithm1) {
        assertEquals(algorithm.getKeyName(), algorithm1.getKeyName());
        assertEquals(algorithm.getKeySpec(), algorithm1.getKeySpec());
        assertEquals(algorithm.getCryptoName(), algorithm1.getCryptoName());
        assertEquals(algorithm.getKeyLen(), algorithm1.getKeyLen());
        assertEquals(algorithm.getValue(), algorithm1.getValue());
        assertEquals(algorithm.getIvLen(), algorithm1.getIvLen());
        assertEquals(algorithm.getTagLen(), algorithm1.getTagLen());
    }

    public static void assertEncryptionContextEquals(Map<String, String> encryptionContext, Map<String, String> encryptionContext1) {
        assertEquals(encryptionContext.size(), encryptionContext1.size());
        encryptionContext.forEach((k, v) -> {
            assert v.equals(encryptionContext1.get(k));
        });
    }

    public static void assertCipherBodyEquals(CipherBody cipherBody, CipherBody actualCipherMaterialCipherBody) {
        assertArrayEquals(cipherBody.getCipherText(), actualCipherMaterialCipherBody.getCipherText());
        assertArrayEquals(cipherBody.getIv(), actualCipherMaterialCipherBody.getIv());
    }

    public static byte[] serializeContext(Map<String, String> encryptionContext) {
        TreeMap<String, String> map = new TreeMap<>(encryptionContext);
        ByteBuffer result = ByteBuffer.allocate(Short.MAX_VALUE);
        result.order(ByteOrder.BIG_ENDIAN);
        result.putInt(encryptionContext.size());
        try {
            for (Map.Entry<String, String> mapEntry: map.entrySet()) {
                byte[] keyBytes = mapEntry.getKey().getBytes(StandardCharsets.UTF_8);
                result.putInt(keyBytes.length);
                result.put(keyBytes);
                byte[] valueBytes = mapEntry.getValue().getBytes(StandardCharsets.UTF_8);
                result.putInt(valueBytes.length);
                result.put(valueBytes);
            }
        } catch (BufferUnderflowException e) {
            throw new AliyunException("encryptionContext must be shorter than " + Short.MAX_VALUE, e);
        }
        result.flip();
        byte[] encryptionContextBytes = new byte[result.limit()];
        result.get(encryptionContextBytes);
        return encryptionContextBytes;
    }
}
