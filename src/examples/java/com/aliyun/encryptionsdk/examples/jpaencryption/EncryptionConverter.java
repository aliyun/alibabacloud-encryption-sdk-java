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

package com.aliyun.encryptionsdk.examples.jpaencryption;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

@Converter
public class EncryptionConverter implements AttributeConverter<String, String> {
    private static String ACCESS_KEY_ID = "<AccessKeyId>";
    private static String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    private static String CMK_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static AliyunConfig config;
    static {
        config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
    }

    @Override
    public String convertToDatabaseColumn(String plainText) {
        DefaultDataKeyProvider defaultDataKeyProvider = new DefaultDataKeyProvider(CMK_ID);
        AliyunCrypto crypto = new AliyunCrypto(config);
        try {
            CryptoResult<byte[]> encryptResult = crypto.encrypt(defaultDataKeyProvider, plainText.getBytes(StandardCharsets.UTF_8), Collections.singletonMap("sample", "context"));
            return Base64.getEncoder().encodeToString(encryptResult.getResult());
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }

    @Override
    public String convertToEntityAttribute(String cipherText) {
        DefaultDataKeyProvider defaultDataKeyProvider = new DefaultDataKeyProvider(CMK_ID);
        AliyunCrypto crypto = new AliyunCrypto(config);
        try {
            CryptoResult<byte[]> decryptResult = crypto.decrypt(defaultDataKeyProvider, Base64.getDecoder().decode(cipherText));
            return new String(decryptResult.getResult(), StandardCharsets.UTF_8);
        } catch (InvalidAlgorithmException | UnFoundDataKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}
