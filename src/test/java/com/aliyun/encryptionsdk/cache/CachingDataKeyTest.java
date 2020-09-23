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

package com.aliyun.encryptionsdk.cache;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.ckm.CachingCryptoKeyManager;
import com.aliyun.encryptionsdk.ckm.DefaultCryptoKeyManager;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import com.aliyun.encryptionsdk.TestAccount;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;

public class CachingDataKeyTest {
    private AliyunCrypto aliyunCrypto;
    private AliyunConfig config;
    private String keyId;
    private LocalDataKeyMaterialCache cache;
    private static final DefaultCryptoKeyManager DEFAULT_CRYPTO_KEY_MANAGER = new DefaultCryptoKeyManager();
    private static final Charset ENCODING = StandardCharsets.UTF_8;

    @Before
    public void setUp() {
        this.config = TestAccount.AliyunKMS.ENCRYPTION_CONFIG;
        this.aliyunCrypto = new AliyunCrypto(config);
        this.keyId = "acs:kms:RegionId:UserId:key/CmkId";
        this.cache = new LocalDataKeyMaterialCache(5);
    }

    @Test
    public void simpleCachingTest(){
        String str = "hello world";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("simple", "test");
        encryptionContext.put("caching", "encrypt");

        CachingCryptoKeyManager cacheCKM = new CachingCryptoKeyManager(new LocalDataKeyMaterialCache());
        aliyunCrypto.setCryptoKeyManager(cacheCKM);

        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(keyId);

        CryptoResult<byte[]> encryptResult = aliyunCrypto.encrypt(dataKeyProvider, str.getBytes(ENCODING), encryptionContext);
        final byte[] cipherResult = encryptResult.getResult();
        assert !Arrays.equals(cipherResult, str.getBytes(ENCODING));

        CryptoResult<byte[]> decrypt = aliyunCrypto.decrypt(dataKeyProvider, cipherResult);
        Map<String, String> encryptionContextDecrypted = decrypt.getEncryptionContext();
        encryptionContext.forEach((k, v) -> {
            assert v.equals(encryptionContextDecrypted.get(k));
        });
        final byte[] decryptResult = decrypt.getResult();
        assertArrayEquals(str.getBytes(ENCODING),decryptResult);
    }

}
