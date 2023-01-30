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

package com.aliyun.encryptionsdk.examples.oss;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.exception.CipherTextParseException;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.handler.Asn1FormatHandler;
import com.aliyun.encryptionsdk.kms.AliyunKms;
import com.aliyun.encryptionsdk.kms.DefaultAliyunKms;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import com.aliyun.oss.OSSClient;
import com.aliyun.oss.common.auth.DefaultCredentialProvider;
import com.aliyun.oss.model.GetObjectRequest;
import com.aliyun.oss.model.OSSObject;
import com.aliyun.oss.model.ObjectMetadata;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * OSS加密上传示例，本示例展示了如何使用EncryptionSDK对OSS上传内容进行加密，解密及分片解密的过程
 * 加密采用AES-GCM模式，分片解密采用AES-CTR模式
 * 为了支持OSS的分片解密，对上传密文内容进行了下面处理：
 * 1、CipherHeader和CipherBody分开进行存储
 * 2、CipherBody拆分为三个部分进行存储
 * 3、CipherHeader作为文件元信息存放到x-oss-meta-header字段
 * 4、CipherBody中的iv作为文件元信息存放到x-oss-meta-iv字段
 * 5、CipherBody中的authTag作为文件元信息存放到x-oss-meta-authTag字段
 * 6、CipherBody中的cipherText为实际存储的密文内容
 */
public class OSSEncryptionSample {
    private static final String ENDPOINT = "oss-cn-hangzhou.aliyuncs.com";
    private static final String ACCESS_KEY_ID = System.getenv("<AccessKeyId>");
    private static final String ACCESS_KEY_SECRET = System.getenv("<AccessKeySecret>");

    private static final String BUCKET_NAME = "<BucketName>";
    private static final String CONTENT = "jdjfhdus6182042795hlnf12s8yhfs976y2nfoshhnsdfsf235bvsmnhtskbcfd!";
    private static final String CMK = "acs:kms:RegionId:UserId:key/CmkId";

    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();
    private static final OSSClient OSS_CLIENT = new OSSClient(ENDPOINT, new DefaultCredentialProvider(ACCESS_KEY_ID, ACCESS_KEY_SECRET), null);

    public static void main(String[] args) {
        try {
            CryptoResult<byte[]> encryptResult = encrypt(CMK, getConfig(), CONTENT.getBytes());
            // 从密文体部获取裸密文文本
            byte[] cipherText = encryptResult.getCipherMaterial().getCipherBody().getCipherText();
            String filePath = upload(new ByteArrayInputStream(cipherText), "test", encryptResult.getCipherMaterial());
            simpleGetObject(filePath);
            rangeGetObject(filePath);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            OSS_CLIENT.shutdown();
        }
    }

    /**
     * 上传密文到OSS
     * @param inputStream 密文
     * @param filePrefix 文件名称前缀
     * @param processInformation 密文材料
     * @return 文件名称
     */
    public static String upload(InputStream inputStream, String filePrefix, CipherMaterial processInformation) {
        //put object
        Calendar c = Calendar.getInstance();
        String filePath = filePrefix + "/" + c.get(Calendar.YEAR) + "/" + (c.get(Calendar.MONTH) + 1) + "/" + c.get(Calendar.DATE) + "/" + c.getTimeInMillis() + ".txt";

        // 创建文件元信息。
        ObjectMetadata meta = new ObjectMetadata();

        CipherHeader cipherHeader = processInformation.getCipherHeader();
        Asn1FormatHandler asn1FormatHandler = new Asn1FormatHandler();
        byte[] cipherHeaderBytes = asn1FormatHandler.serializeCipherHeader(cipherHeader);
        byte[] iv = processInformation.getCipherBody().getIv();
        byte[] authTag = processInformation.getCipherBody().getAuthTag();

        // 设置自定义元信息(头信息,iv向量信息,认证tag)
        String cipherHeaderString = BASE64_ENCODER.encodeToString(cipherHeaderBytes);
        meta.addUserMetadata("x-oss-meta-header", cipherHeaderString);
        String ivString = BASE64_ENCODER.encodeToString(iv);
        meta.addUserMetadata("x-oss-meta-iv", ivString);
        String authTagString = BASE64_ENCODER.encodeToString(authTag);
        meta.addUserMetadata("x-oss-meta-authTag", authTagString);

        // 将加密后的文件和自定义的元信息上传到oss
        OSS_CLIENT.putObject(BUCKET_NAME, filePath, inputStream, meta);
        return filePath;
    }

    /**
     * 获取完整密文对象并解密
     * @param filePath 文件名称
     * @throws IOException IO异常
     */
    public static void simpleGetObject(String filePath) throws IOException {
        // 首先获取文件元信息
        ObjectMetadata objectMetadata = OSS_CLIENT.getObjectMetadata(BUCKET_NAME, filePath);
        Map<String, String> userMetadata = objectMetadata.getUserMetadata();
        // 从文件元信息中读取CipherHeader
        byte[] cipherHeaderInfo = BASE64_DECODER.decode(userMetadata.get("x-oss-meta-header"));
        // 从文件元信息中读取CipherBody中的iv
        byte[] iv = BASE64_DECODER.decode(userMetadata.get("x-oss-meta-iv"));
        // 从文件元信息中读取CipherBody中的authTag
        byte[] authTag = BASE64_DECODER.decode(userMetadata.get("x-oss-meta-authTag"));

        // 获取密文对象
        OSSObject ossObject = OSS_CLIENT.getObject(BUCKET_NAME, filePath);
        byte[] streamResult = readAllBytes(ossObject.getObjectContent());
        // 解密
        byte[] bytes = decrypt(CMK, getConfig(), streamResult, cipherHeaderInfo, iv, authTag);

        System.out.println("Put plain text:" + CONTENT);
        System.out.println("Get and decrypted text:" + new String(bytes, StandardCharsets.UTF_8));
    }

    /**
     * 分片获取密文对象并解密
     * @param filePath 文件名称
     * @throws IOException IO异常
     */
    public static void rangeGetObject(String filePath) throws IOException {
        // 首先获取文件元信息
        ObjectMetadata objectMetadata = OSS_CLIENT.getObjectMetadata(BUCKET_NAME, filePath);
        Map<String, String> userMetadata = objectMetadata.getUserMetadata();
        // 从文件元信息中读取CipherHeader
        byte[] cipherHeaderInfo = BASE64_DECODER.decode(userMetadata.get("x-oss-meta-header"));
        // 从文件元信息中读取CipherBody中的iv
        byte[] nonce = BASE64_DECODER.decode(userMetadata.get("x-oss-meta-iv"));

        // 分片获取密文对象
        int start = 10;
        int end = 35;
        GetObjectRequest getObjectRequest = new GetObjectRequest(BUCKET_NAME, filePath);
        getObjectRequest.setRange(start, end);
        OSSObject ossObject = OSS_CLIENT.getObject(getObjectRequest);
        byte[] rangeStreamResult = readAllBytes(ossObject.getObjectContent());

        // 解密
        byte[] rangeBytes = rangeDecrypt(CMK, getConfig(), start, rangeStreamResult, cipherHeaderInfo, nonce);
        System.out.println("Range-Get plain text:" + CONTENT.substring(start, end + 1));
        System.out.println("Range-Get decrypted text:" + new String(rangeBytes, StandardCharsets.UTF_8));
    }

    /**
     * 对上传OSS内容进行加密(使用默认gcm模式)
     * @param keyId 主密钥
     * @param config 配置
     * @param plainText 待加密的内容
     * @return 密文
     */
    private static CryptoResult<byte[]> encrypt(final String keyId, AliyunConfig config, byte[] plainText) {
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);

        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(keyId);

        try {
            return aliyunCrypto.encrypt(dataKeyProvider, plainText, Collections.emptyMap());
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }

    /**
     * 完整密文对象解密
     * @param keyId 主密钥
     * @param config 配置
     * @param cipherText 待解密密文
     * @param cipherHeaderBytes 密文头
     * @param iv 密文体随机向量
     * @param authTag 验证tag
     * @return 明文
     */
    private static byte[] decrypt(final String keyId, AliyunConfig config, byte[] cipherText, byte[] cipherHeaderBytes, byte[] iv, byte[] authTag) {
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);

        Asn1FormatHandler asn1FormatHandler = new Asn1FormatHandler();
        CryptoResult<byte[]> decryptResult = null;
        try {
            // 构建密文头部
            CipherHeader cipherHeader = asn1FormatHandler.deserializeCipherHeader(cipherHeaderBytes);
            // 构建密文体部
            CipherBody cipherBody = new CipherBody(iv, cipherText, authTag);
            // 构建密文材料
            CipherMaterial cipherMaterial = new CipherMaterial(cipherHeader, cipherBody);
            byte[] serializeCipherText = asn1FormatHandler.serialize(cipherMaterial);
            // 解密
            decryptResult = aliyunCrypto.decrypt(new DefaultDataKeyProvider(keyId), serializeCipherText);
            return decryptResult.getResult();
        } catch (CipherTextParseException | InvalidAlgorithmException | UnFoundDataKeyException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }

    /**
     * 分片解密(使用ctr模式)
     * @param keyId 主密钥
     * @param config 配置
     * @param offset 密文起始偏移
     * @param cipherText 待解密分片密文
     * @param cipherHeaderBytes 密文头
     * @param iv 密文体随机向量
     * @return 明文
     */
    private static byte[] rangeDecrypt(final String keyId, AliyunConfig config, Integer offset, byte[] cipherText, byte[] cipherHeaderBytes, byte[] iv) {
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);

        Asn1FormatHandler asn1FormatHandler = new Asn1FormatHandler();
        try {
            // 构建密文头部
            CipherHeader cipherHeader = asn1FormatHandler.deserializeCipherHeader(cipherHeaderBytes);
            List<EncryptedDataKey> datakeyList = cipherHeader.getEncryptedDataKeys();
            EncryptedDataKey encDataKey = datakeyList.get(0);

            byte[] datakeyBytes = decryptDataKey(encDataKey, cipherHeader.getEncryptionContext());
            SecretKeySpec keySpec = new SecretKeySpec(datakeyBytes, cipherHeader.getAlgorithm().getKeyName());


            // 计算当前分片密文起始分组位置，如果分片头与分组位置不对齐, 需要进行填充
            int needPaddingLen = offset % cipherHeader.getAlgorithm().getBlockSize();
            byte[] cipherTextPadBytes = paddingCipherText(cipherText, needPaddingLen);
            // 构建密文体部，体部iv长度在gcm模式下为12，ctr模式为16，需要进行填充
            byte[] ctrIV = paddingIV(iv, offset);

            byte[] decryptBytes = decryptCTR( cipherTextPadBytes, keySpec, ctrIV, cipherHeader.getAlgorithm().getCryptoName());

            // 去掉填充内容并返回结果
            return unPaddingPlaintext(decryptBytes, needPaddingLen);
        } catch (CipherTextParseException | InvalidAlgorithmException | UnFoundDataKeyException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        } catch (Exception e){
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }

    public static byte[] decryptCTR(byte[] cipherText, SecretKeySpec keySpec, byte[] ctrIV, String headerCipherSpec) throws Exception
    {
        String ctrCipherSpec;
        if(headerCipherSpec.equals("AES/GCM/NoPadding"))
            ctrCipherSpec = "AES/CTR/NoPadding";
        else if(headerCipherSpec.equals("SM4/GCM/NoPadding"))
            ctrCipherSpec = "SM4/CTR/NoPadding";
        else
            throws new Exception("Error Crypto cipher spec");
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(ctrCipherSpec);

        // Create IVParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(ctrIV);

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return decryptedText;
    }

    public static byte[] decryptDataKey(EncryptedDataKey encDatakey, Map<String,String> context){
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        DefaultAliyunKms aliyunKms = new DefaultAliyunKms(config);

        AliyunKms.DecryptDataKeyResult decDataKeyRes = aliyunKms.decryptDataKey(encDatakey, context);
        byte[] datakey = org.bouncycastle.util.encoders.Base64.decode(decDataKeyRes.getPlaintext());
        return datakey;
    }

    /**
     * 对分片密文未分组对齐部分进行填充
     * @param cipherText 分片密文
     * @param paddingLen 未分组对齐偏移，即需要填充的长度
     * @return 填充结果
     */
    private static byte[] paddingCipherText(byte[] cipherText, Integer paddingLen) {
        byte[] padBuffer = new byte[paddingLen + cipherText.length];
        System.arraycopy(cipherText, 0, padBuffer, paddingLen, cipherText.length);
        return padBuffer;
    }

    /**
     * ctr模式下iv长度为16, 前12字节为gcm模式iv, 后4字节为计数器信息，此函数对gcm的iv进行填充, 将计数器信息放到最后
     * @param iv gcm模式密文体部随机向量
     * @param offset 分片密文起始偏移
     * @return 填充后ctr模式iv
     */
    private static byte[] paddingIV(byte[] iv, Integer offset) {
        byte[] ctrIV = new byte[16];
        System.arraycopy(iv, 0, ctrIV, 0, iv.length);
        int n = offset / (Integer) 16 + 2;
        ctrIV[15] = (byte) (n & 0xff);
        ctrIV[14] = (byte) (n >> 8 & 0xff);
        ctrIV[13] = (byte) (n >> 16 & 0xff);
        ctrIV[12] = (byte) (n >> 24 & 0xff);
        return ctrIV;
    }

    /**
     * 清除解密之后的分片明文中分组对齐填充部分
     * @param plaintext 解密后包含分组对齐填充的分片明文
     * @param unPaddingLen 未分组对齐偏移，即需要填充的长度
     * @return 不包含填充的分片明文
     */
    private static byte[] unPaddingPlaintext(byte[] plaintext, Integer unPaddingLen) {
        byte[] unPadBuffer = new byte[plaintext.length - unPaddingLen];
        System.arraycopy(plaintext, unPaddingLen, unPadBuffer, 0, plaintext.length - unPaddingLen);
        return unPadBuffer;
    }

    private static AliyunConfig getConfig() {
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        return config;
    }

    private static byte[] readAllBytes(InputStream is) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] bytes = new byte[1024];
            int len;
            while ((len = is.read(bytes)) != -1) {
                bos.write(bytes, 0, len);
            }
            bos.close();
            return bos.toByteArray();
        } catch (IOException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return null;
    }
}
