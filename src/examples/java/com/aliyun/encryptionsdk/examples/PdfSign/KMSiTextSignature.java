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

package com.aliyun.encryptionsdk.examples.PdfSign;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.model.SignatureAlgorithm;
import com.aliyun.encryptionsdk.model.ContentType;
import com.aliyun.encryptionsdk.provider.KmsAsymmetricKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.itextpdf.kernel.PdfException;
import com.itextpdf.signatures.IExternalSignature;

/**
 * KMS签名
 */
public class KMSiTextSignature implements IExternalSignature {
    public DefaultAcsClient kmsClient;
    public String keyId;
    public String algorithm;
    public String keyVersionId;
    public String hashAlgorithm;
    // change with your regionId
    public static final String REGION_ID = "cn-hangzhou";
    // your AccessKeyId
    public static final String ACCESS_KEY_ID = "<AccessKeyId>";
    // your AccessKeySecret
    public static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    private static AliyunCrypto aliyunCrypto;

    static {
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        aliyunCrypto = new AliyunCrypto(config);
    }

    @Override
    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return this.algorithm;
    }

    @Override
    public byte[] sign(byte[] message) {
        SignatureProvider keyProvider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, getKmsAlgorithm());
        return aliyunCrypto.sign(keyProvider, message, ContentType.MESSAGE).getResult();
    }

    private SignatureAlgorithm getKmsAlgorithm(){
        if (this.algorithm.equals("RSA")) {
            return SignatureAlgorithm.RSA_PKCS1_SHA_256;
        } else if (this.algorithm.equals("DSA")) {
            return SignatureAlgorithm.SM2DSA;
        } else {
            if (!this.algorithm.equals("ECDSA")) {
                throw (new PdfException("Unknown KmsAlgorithm: {0}.")).setMessageParams(algorithm);
            }
            return SignatureAlgorithm.ECDSA_P256_SHA_256;
        }
    }

    public DefaultAcsClient kmsClient() {
        IClientProfile profile = DefaultProfile.getProfile(REGION_ID, ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }
}
