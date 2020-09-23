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

package com.aliyun.encryptionsdk.examples.provider;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.SecretManagerDataKeyProvider;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;

/**
 * SecretManagerProvider使用示例(自动存储凭据)
 */
public class SecretManagerProviderSample {
    // accessKeyId accessKeySecret
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    // cmkId
    private static final String CMK = "acs:kms:RegionId:UserId:key/CmkId";
    private static final byte[] PLAIN_TEXT = "this is test.".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        // 存储到secretManager中的name 若secretName已经存在，则直接查询secretValue并返回
        String secretName = "testSecretManagerProvider";
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        // 加密
        CryptoResult<byte[]> encryptResult = encrypt(config, PLAIN_TEXT, secretName);
        // 使用SecretManagerDataKeyProvider解密
        CryptoResult<byte[]> decryptResult = decrypt(secretName, config, encryptResult.getResult());
        assertArrayEquals(PLAIN_TEXT, decryptResult.getResult());
    }

    /**
     * 加密操作
     * @param config    ak,sk配置信息
     * @param plainText 原文的字节数组
     * @param secretName 存放secretManager中使用的凭据名
     * @return          加密结果
     */
    private static CryptoResult<byte[]> encrypt(AliyunConfig config, byte[] plainText, String secretName) {
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);
        BaseDataKeyProvider dataKeyProvider = new SecretManagerDataKeyProvider(CMK, secretName);
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("this", "context");
        encryptionContext.put("can help you", "to confirm");
        encryptionContext.put("this data", "is your original data");
        try {
            return aliyunCrypto.encrypt(dataKeyProvider, plainText, encryptionContext);
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        } catch (AliyunException e){
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }

    /**
     * 解密
     * @param secretName 凭据名
     * @param config
     * @param cipherText 加密材料的body信息
     * @return
     */
    private static CryptoResult<byte[]> decrypt(String secretName, AliyunConfig config, byte[] cipherText){
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);
        BaseDataKeyProvider provider = new SecretManagerDataKeyProvider(CMK, secretName);
        try {
            return aliyunCrypto.decrypt(provider, cipherText);
        } catch (InvalidAlgorithmException | UnFoundDataKeyException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        } catch (AliyunException e){
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }


}
