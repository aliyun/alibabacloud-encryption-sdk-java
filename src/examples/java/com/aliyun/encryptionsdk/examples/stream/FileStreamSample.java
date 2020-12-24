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

package com.aliyun.encryptionsdk.examples.stream;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.examples.SimpleEncryptAndDecryptSample;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

public class FileStreamSample {
    private static final String FILE = "README.md";
    // accessKeyId accessKeySecret
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    // 日志系统
    private static final Logger LOGGER = LoggerFactory.getLogger(FileStreamSample.class);
    // cmkId
    private static final String CMK_ARN = "acs:kms:RegionId:UserId:key/CmkId";

    public static void main(String[] args) throws IOException {
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        encryptStream(config);
        decryptStream(config);
        Assert.assertEquals(getFileMD5(FILE), getFileMD5(FILE + ".decrypted"));
    }

    private static void encryptStream(AliyunConfig config) throws IOException {
        //1.创建SDK，传入访问aliyun配置
        AliyunCrypto aliyunSDK = new AliyunCrypto(config);

        //2.构建加密上下文
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("this", "context");
        encryptionContext.put("can help you", "to confirm");
        encryptionContext.put("this data", "is your original data");

        //3.创建提供数据密钥的provider
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(CMK_ARN);

        //4.创建输入输出流
        FileInputStream inputStream = new FileInputStream(FILE);
        FileOutputStream outputStream = new FileOutputStream(FILE + ".encrypted");

        //5.调用加密接口
        try {
            aliyunSDK.encrypt(provider, inputStream, outputStream, encryptionContext);
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
    }

    private static void decryptStream(AliyunConfig config) throws IOException {
        //1.创建SDK，传入访问aliyun配置
        AliyunCrypto aliyunSDK = new AliyunCrypto(config);

        //2.创建提供数据密钥的provider
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(CMK_ARN);

        //3.创建输入输出流
        FileInputStream inputStream = new FileInputStream(FILE + ".encrypted");
        FileOutputStream outputStream = new FileOutputStream(FILE + ".decrypted");

        //4.调用解密接口
        try {
            aliyunSDK.decrypt(provider, inputStream, outputStream);
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
    }

    private static String getFileMD5(String fileName) {
        File file = new File(fileName);
        if  (!file.isFile()) {
            return null;
        }
        MessageDigest digest;
        byte[] buffer = new byte[4096];
        try (FileInputStream in = new FileInputStream(file)){
            digest = MessageDigest.getInstance("MD5");
            int len;
            while  ((len = in.read(buffer)) != -1) {
                digest.update(buffer,  0 , len);
            }
            return Hex.encodeHexString(digest.digest());
        }  catch  (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}