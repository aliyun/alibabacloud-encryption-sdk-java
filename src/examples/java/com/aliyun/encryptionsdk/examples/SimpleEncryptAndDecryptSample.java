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

package com.aliyun.encryptionsdk.examples;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;


/**
 * 基础加解密功能（单region单cmk）
 *
 */
public class SimpleEncryptAndDecryptSample {
    // 明文
    private static final byte[] PLAIN_TEXT = "this is test.".getBytes(StandardCharsets.UTF_8);
    // accessKeyId accessKeySecret
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    // 日志系统
    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleEncryptAndDecryptSample.class);
    // cmkId
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";

    public static void main(final String[] args) {
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        CryptoResult<byte[]> encryptResult = encryptSample(config, PLAIN_TEXT);
        CryptoResult<byte[]> decryptResult = decryptSample(config, encryptResult.getResult());
        assertArrayEquals(PLAIN_TEXT, decryptResult.getResult());
    }

    /**
     *
     *
     * @param config
     * @param plainText 明文的字节数组
     * @return          加密结果和加密材料信息
     */
    private static CryptoResult<byte[]> encryptSample(AliyunConfig config, byte[] plainText) {
        // 1、构建sdk(可以指定自定义加密处理器和日志)
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);
//        AliyunCrypto aliyunCrypto = new AliyunCrypto(encryptHandler, config, LOGGER);

        // 2、构建provider
        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(KEY_ID);

        // 3、构建加密上下文
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("this", "context");
        encryptionContext.put("can help you", "to confirm");
        encryptionContext.put("this data", "is your original data");

        // 4、sdk加密
        try {
            return aliyunCrypto.encrypt(dataKeyProvider, plainText, encryptionContext);
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }

    /**
     *
     *
     * @param config
     * @param cipherText 密文的字节数组
     * @return           解密结果和解密材料信息
     */
    private static CryptoResult<byte[]> decryptSample(AliyunConfig config, byte[] cipherText) {
        // 1、构建sdk
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);

        // 2、构建provider
        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(KEY_ID);

        // 3、sdk解密
        try {
            return aliyunCrypto.decrypt(dataKeyProvider, cipherText);
        } catch (InvalidAlgorithmException | UnFoundDataKeyException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }
}
