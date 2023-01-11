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

package com.aliyun.encryptionsdk.examples.cache;


import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.cache.LocalDataKeyMaterialCache;
import com.aliyun.encryptionsdk.ckm.CachingCryptoKeyManager;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 *
 * 缓存ckm使用示例
 */
public class CacheEncryptionSample {
    private static final String ACCESS_KEY_ID = System.getenv("<AccessKeyId>");
    private static final String ACCESS_KEY_SECRET = System.getenv("<AccessKeySecret>");
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        //1.创建访问aliyun配置
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);

        //2.创建SDK，传入访问aliyun配置
        AliyunCrypto aliyunSDK = new AliyunCrypto(config);
        // 设置缓存ckm
        CachingCryptoKeyManager cacheCKM = new CachingCryptoKeyManager(new LocalDataKeyMaterialCache());
        // 设置缓存存活时间
        cacheCKM.setMaxSurvivalTime(1000 * 60);
        // 设置密钥最大加密字节数
        cacheCKM.setMaxEncryptionBytes(1000);
        // 设置密钥最大加密消息数
        cacheCKM.setMaxEncryptionMessages(10);
        aliyunSDK.setCryptoKeyManager(cacheCKM);

        //3.创建provider，用于提供数据密钥或签名
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(KEY_ID);

        //4.加密上下文
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("this", "context");
        encryptionContext.put("can help you", "to confirm");
        encryptionContext.put("this data", "is your original data");
        CryptoResult<byte[]> cipherResult1 = null;
        CryptoResult<byte[]> cipherResult2 = null;

        try {
            //5.调用加密接口
            cipherResult1 = aliyunSDK.encrypt(provider, PLAIN_TEXT, encryptionContext);
            //希望命中缓存使用同一个加密密钥材料
            cipherResult2 = aliyunSDK.encrypt(provider, PLAIN_TEXT, encryptionContext);
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        //两次加密的dataKey相同
        assertEncryptedDataKeysEquals(cipherResult1.getCipherMaterial().getCipherHeader().getEncryptedDataKeys(),
                cipherResult2.getCipherMaterial().getCipherHeader().getEncryptedDataKeys());
        System.out.println("Hit The Cache");
    }

    private static void assertEncryptedDataKeysEquals(List<EncryptedDataKey> encryptedDataKeys, List<EncryptedDataKey> encryptedDataKeys1) {
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
}
