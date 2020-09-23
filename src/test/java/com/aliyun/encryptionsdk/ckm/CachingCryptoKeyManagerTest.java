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

import com.aliyun.encryptionsdk.cache.DataKeyCache;
import com.aliyun.encryptionsdk.cache.LocalDataKeyMaterialCache;
import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.handler.DefaultEncryptHandler;
import com.aliyun.encryptionsdk.model.CipherMaterial;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.model.DecryptionMaterial;
import com.aliyun.encryptionsdk.model.EncryptionMaterial;
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import static com.aliyun.encryptionsdk.TestFixtures.createDefaultDataKeyProvider;
import static org.junit.Assert.*;

public class CachingCryptoKeyManagerTest {
    private static DataKeyCache.UsageInfo USAGE_INFO;
    private DataKeyCache cache;
    private CryptoKeyManager delegate;
    private CachingCryptoKeyManager ckm;
    private static final long MAX_SURVIVAL_TIME = 1000;
    private static final long MAX_ENCRYPTION_BYTES = 2048;
    private static final long MAX_ENCRYPTION_MESSAGES = 3;
    private static final Charset ENCODING = StandardCharsets.UTF_8;
    private static final String PLAIN_TEXT = "this is test.";
    private static CryptoAlgorithm defaultAlgorithm;

    @Before
    public void setUp() {
        USAGE_INFO = new DataKeyCache.UsageInfo(0, 0);
        delegate = new DefaultCryptoKeyManager();
        cache = new LocalDataKeyMaterialCache();
        EncryptionMaterial materialsResult = TestFixtures.createMaterialsResult(1);
        defaultAlgorithm = CryptoAlgorithm.AES_GCM_NOPADDING_256;
        cache.putEncryptEntry(getCacheId(defaultAlgorithm, Collections.singletonMap("index", "1")), 1000, materialsResult, USAGE_INFO);

        ckm = new CachingCryptoKeyManager(cache);
        ckm.setMaxSurvivalTime(MAX_SURVIVAL_TIME);
        ckm.setMaxEncryptionBytes(MAX_ENCRYPTION_BYTES);
        ckm.setMaxEncryptionMessages(MAX_ENCRYPTION_MESSAGES);
    }

    @Test
    public void testCacheMiss() throws InterruptedException {
        EncryptionMaterial encryptDataKeyMaterial = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 500);
        EncryptionMaterial encryptDataKeyMaterial1 = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 500);
        assertSame(encryptDataKeyMaterial, encryptDataKeyMaterial1);
        Thread.sleep(1001);
        EncryptionMaterial encryptDataKeyMaterial2 = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 500);
        assertNotSame(encryptDataKeyMaterial, encryptDataKeyMaterial2);
    }

    @Test
    public void testMaxEncryptionBytes(){
        EncryptionMaterial encryptDataKeyMaterial = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 700);
        EncryptionMaterial encryptDataKeyMaterial1 = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 700);
        assertSame(encryptDataKeyMaterial, encryptDataKeyMaterial1);
        EncryptionMaterial encryptDataKeyMaterial2 = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 700);
        // 700 * 3 > 2048
        assertNotSame(encryptDataKeyMaterial, encryptDataKeyMaterial2);
    }

    @Test
    public void testMaxEncryptionMessages(){
        EncryptionMaterial encryptDataKeyMaterial = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 500);
        EncryptionMaterial encryptDataKeyMaterial1 = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 500);
        EncryptionMaterial encryptDataKeyMaterial2 = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 500);
        EncryptionMaterial encryptDataKeyMaterial3 = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(), Collections.singletonMap("index", "1"), 500);
        assertSame(encryptDataKeyMaterial, encryptDataKeyMaterial1);
        assertSame(encryptDataKeyMaterial, encryptDataKeyMaterial2);
        //maxMessage = 3
        assertNotSame(encryptDataKeyMaterial, encryptDataKeyMaterial3);
    }

    @Test
    public void testGetEncryptDataKeyMaterialAndGetDecryptDataKeyMaterial(){
        EncryptionMaterial encryptDataKeyMaterial = ckm.getEncryptDataKeyMaterial(createDefaultDataKeyProvider(),
                Collections.singletonMap("index", "1"), 500);
        DefaultEncryptHandler encryptHandler = new DefaultEncryptHandler();
        CipherMaterial encryptMaterial = encryptHandler.encrypt(PLAIN_TEXT.getBytes(), encryptDataKeyMaterial);
        DecryptionMaterial decryptionMaterial = ckm.getDecryptDataKeyMaterial(createDefaultDataKeyProvider(),
                Collections.singletonMap("index", "1"), encryptDataKeyMaterial.getEncryptedDataKeys());
        byte[] decrypt = encryptHandler.decrypt(encryptMaterial, decryptionMaterial);
        assertArrayEquals(PLAIN_TEXT.getBytes(), decrypt);
    }


    private String getCacheId(CryptoAlgorithm algorithm, Map<String, String> encryptionContext) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA");
            digestAlgorithm(digest, algorithm);
            digestContext(digest, encryptionContext);
            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new AliyunException("SHA MessageDigest not available", e);
        }
    }
    private void digestAlgorithm(MessageDigest digest, CryptoAlgorithm algorithm) {
        if (algorithm == null) {
            digest.update((byte) 0);
        } else {
            digest.update((byte) 1);
            algorithm.digestAlgorithm(digest);
        }
    }

    private void digestContext(MessageDigest digest, Map<String,String> encryptionContext) {
        if (encryptionContext == null) {
            digest.update((byte) 0);
        } else {
            digest.update((byte) 1);
            digest.update((byte) encryptionContext.size());
            TreeMap<String, String> map = new TreeMap<>(encryptionContext);
            map.forEach((key, value) -> {
                digest.update(key.getBytes(ENCODING));
                digest.update(value.getBytes(ENCODING));
            });
        }
    }
}

