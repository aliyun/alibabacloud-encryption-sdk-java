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

package com.aliyun.encryptionsdk.examples.signVerify;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.kms.DefaultAliyunKms;
import com.aliyun.encryptionsdk.model.ContentType;
import com.aliyun.encryptionsdk.model.SignatureAlgorithm;
import com.aliyun.encryptionsdk.model.SignatureResult;
import com.aliyun.encryptionsdk.provider.KmsAsymmetricKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;

import static org.junit.Assert.assertTrue;


/**
 *
 * 消息摘要签名验签
 */
public class DigestMessageSignatureVerifySample {
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String KEY_VERSION_ID = "<KEY_VERSION_ID>";
    // accessKeyId accessKeySecret
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    private static final byte[] PLAIN_TEXT = "this is test.".getBytes();

    public static void main(String[] args) {
        SignatureResult<byte[]> signature = signSample(PLAIN_TEXT);
        boolean isOk = verifySample(PLAIN_TEXT, signature.getResult());
        assertTrue(isOk);
    }

    private static boolean verifySample(byte[] plainText, byte[] result) {
        // 1、构建包含AccessKey AccessKeySecret信息的config
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        // 2、构建sdk
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);
        // 3、构建签名验签dataKeyProvider
        KmsAsymmetricKeyProvider provider = new KmsAsymmetricKeyProvider(KEY_ID, KEY_VERSION_ID, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        //    算法为sm2时 需要kms获取公钥
//        KmsAsymmetricKeyProvider provider = new KmsAsymmetricKeyProvider(KEY_ID, KEY_VERSION_ID, SignatureAlgorithm.SM2DSA);
//        provider.setAliyunKms(new DefaultAliyunKms(config));
        // 4、计算摘要
        byte[] digest = provider.getDigest(plainText);
        byte[] sha256Digest = getDigestBytes(digest);
        // 5、sdk验签并返回结果
        try {
            SignatureResult<Boolean> verifyResult = aliyunCrypto.verify(provider, sha256Digest, result, ContentType.DIGEST);
            return verifyResult.getResult();
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return false;
    }

    private static SignatureResult<byte[]> signSample(byte[] plainText) {
        // 1、构建包含AccessKey AccessKeySecret信息的config
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        // 2、构建sdk
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);
        // 3、构建签名验签dataKeyProvider(keyId支持sm2 使用sm2时provider中需要指定算法)
        KmsAsymmetricKeyProvider provider = new KmsAsymmetricKeyProvider(KEY_ID, KEY_VERSION_ID, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        //    算法为sm2时 需要kms获取公钥
//        KmsAsymmetricKeyProvider provider = new KmsAsymmetricKeyProvider(KEY_ID, KEY_VERSION_ID, SignatureAlgorithm.SM2DSA);
//        provider.setAliyunKms(new DefaultAliyunKms(config));

        // 4、计算摘要
        byte[] digest = provider.getDigest(plainText);
        byte[] sha256Digest = getDigestBytes(digest);
        // 5、sdk签名并返回结果
        return aliyunCrypto.sign(provider, sha256Digest, ContentType.DIGEST);
    }

    private static byte[] getDigestBytes(byte[] digest){
        String hexResult = bytes2Hex(digest);
        return hex2Bytes(hexResult);
    }

    private static byte[] hex2Bytes(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    private static String bytes2Hex(byte[] bytes) {
        final byte[] hexArray = "0123456789ABCDEF".getBytes();
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
