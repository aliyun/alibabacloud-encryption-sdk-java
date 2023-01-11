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
import com.aliyun.encryptionsdk.model.ContentType;
import com.aliyun.encryptionsdk.model.SignatureAlgorithm;
import com.aliyun.encryptionsdk.model.SignatureResult;
import com.aliyun.encryptionsdk.provider.KmsAsymmetricKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;

import static org.junit.Assert.assertTrue;

/**
 * 使用原始消息签名验签
 */
public class OriginalMessageSignatureVerifySample {
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String KEY_VERSION_ID = "keyVersionId";
    // accessKeyId accessKeySecret
    private static final String ACCESS_KEY_ID = System.getenv("<AccessKeyId>");
    private static final String ACCESS_KEY_SECRET = System.getenv("<AccessKeySecret>");

    public static void main(String[] args) {
        byte[] msg = "this is test.".getBytes();
        SignatureResult<byte[]> signature = signSample(msg);
        boolean isOk = verifySample(msg, signature.getResult());
        assertTrue(isOk);
    }

    private static boolean verifySample(byte[] msg, byte[] signature) {
        // 1、构建包含AccessKey AccessKeySecret信息的config
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        // 2、构建sdk
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);
        // 3、构建签名验签dataKeyProvider
        SignatureProvider provider = new KmsAsymmetricKeyProvider(KEY_ID, KEY_VERSION_ID, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        // 4、sdk验签并返回结果
        try {
            Boolean verifyResult = aliyunCrypto.verify(provider, msg, signature, ContentType.MESSAGE);
            return verifyResult;
        } catch (InvalidAlgorithmException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        return false;
    }

    private static SignatureResult<byte[]> signSample(byte[] msg) {
        // 1、构建包含AccessKey AccessKeySecret信息的config
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        // 2、构建sdk
        AliyunCrypto aliyunCrypto = new AliyunCrypto(config);
        // 3、构建签名验签dataKeyProvider
        SignatureProvider provider = new KmsAsymmetricKeyProvider(KEY_ID, KEY_VERSION_ID, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        // 4、sdk签名并返回结果
        return aliyunCrypto.sign(provider, msg, ContentType.MESSAGE);

    }
}
