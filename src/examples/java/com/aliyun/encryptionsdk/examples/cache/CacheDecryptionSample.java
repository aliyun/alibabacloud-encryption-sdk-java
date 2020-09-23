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
import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class CacheDecryptionSample {
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    private static final String KEY_ID = "acs:kms:cn-beijing:userId:key/keyId";
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
        cacheCKM.setMaxSurvivalTime(1000 * 2);
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
        SecretKey plaintextDataKey1 = null;
        SecretKey plaintextDataKey2 = null;
        try {
            //5.调用加密接口
            CryptoResult<byte[]> cipherResult = aliyunSDK.encrypt(provider, PLAIN_TEXT, encryptionContext);
            CryptoResult<byte[]> decryptResult1 = aliyunSDK.decrypt(provider, cipherResult.getResult());
            CryptoResult<byte[]> decryptResult2 = aliyunSDK.decrypt(provider, cipherResult.getResult());
            // 两次解密使用的dataKey是同一个
            plaintextDataKey1 = cacheCKM.getDecryptDataKeyMaterial(provider, encryptionContext, decryptResult1.getEncryptedDataKeyList()).getPlaintextDataKey();
            plaintextDataKey2 = cacheCKM.getDecryptDataKeyMaterial(provider, encryptionContext, decryptResult2.getEncryptedDataKeyList()).getPlaintextDataKey();
        } catch (InvalidAlgorithmException e){
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        } catch (AliyunException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }

        if (plaintextDataKey1 == plaintextDataKey2){
            System.out.println("Hit The Cache");
            return;
        }
        System.out.println("Miss The Cache");
    }
}
