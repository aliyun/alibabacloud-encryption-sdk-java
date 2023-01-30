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

package com.aliyun.encryptionsdk.examples.multi;

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
import java.util.*;

import static org.junit.Assert.assertArrayEquals;

/**
 * 多CMK加解密(支持多region)
 *
 */
public class MultiCmkSample {
    // 明文
    private static final byte[] PLAIN_TEXT = "this is test.".getBytes(StandardCharsets.UTF_8);
    // accessKeyId accessKeySecret
    private static final String ACCESS_KEY_ID = System.getenv("<AccessKeyId>");
    private static final String ACCESS_KEY_SECRET = System.getenv("<AccessKeySecret>");
    // 日志系统
    private static final Logger LOGGER = LoggerFactory.getLogger(MultiCmkSample.class);
    // cmkId
    private static final String MASTER_CMK_ARN = "acs:kms:cn-beijing:userId:key/keyId";
    private static final String SHANGHAI_KEY_ARN = "acs:kms:cn-shanghai:userId:key/keyId";
    private static final String HANGZHOU_KEY_ARN = "acs:kms:cn-hangzhou:userId:key/keyId";

    public static void main(final String[] args) {
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        
        List<String> keyIds = new ArrayList<>();
        // 不同的cmkId(支持多region)
        keyIds.add(SHANGHAI_KEY_ID);
        keyIds.add(HANGZHOU_KEY_ARN);

        // 对数据进行加密
        CryptoResult<byte[]> encryptResult = encryptSample(config, keyIds, PLAIN_TEXT);

        // 指定一个cmk进行解密
        CryptoResult<byte[]> shanghaiDecryptResult = decryptSample(config, SHANGHAI_KEY_ID, encryptResult.getResult());
        CryptoResult<byte[]> beijingDecryptResult = decryptSample(config, HANGZHOU_KEY_ARN, encryptResult.getResult());
        assertArrayEquals(PLAIN_TEXT, shanghaiDecryptResult.getResult());
        assertArrayEquals(PLAIN_TEXT, beijingDecryptResult.getResult());
    }

    /**
     *
     *
     * @param config
     * @param keyIds    保护dataKey的多个cmk的集合
     * @param plainText 明文的字节数组
     * @return          加密结果和加密材料信息
     */
    private static CryptoResult<byte[]> encryptSample(AliyunConfig config, List<String> keyIds, byte[] plainText) {
        // 1、构建sdk(可以指定自定义加密处理器和日志)
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);

        // 2、设置主地域CMK ARN，在主地域调用KMS GenerateDataKey生成数据密钥(DataKey)
        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(MASTER_CMK_ARN);
        // 构建多cmk的dataKeyProvider
        dataKeyProvider.setMultiCmkId(keyIds);

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
     * @param cipherText 加密密文
     * @return           加密结果和加密材料信息
     */

    private static CryptoResult<byte[]> decryptSample(AliyunConfig config, String cmk, byte[] cipherText) {
        // 1、构建sdk
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);

        // 2、构建dataKeyProvider
        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(cmk);

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
