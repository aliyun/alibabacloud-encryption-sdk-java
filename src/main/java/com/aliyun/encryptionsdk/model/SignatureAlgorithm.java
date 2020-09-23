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

package com.aliyun.encryptionsdk.model;

/**
 * KMS非对称密钥签名算法，详情请参考：
 * https://help.aliyun.com/document_detail/148132.html?spm=a2c4g.11186623.6.631.3fd17338YrLWEL
 */
public enum SignatureAlgorithm {

    // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    RSA_PSS_SHA_256("RSA_2048", "RSA_PSS_SHA_256", "SHA-256"),

    // RSASSA-PKCS1-v1_5 using SHA-256
    RSA_PKCS1_SHA_256("RSA_2048", "RSA_PKCS1_SHA_256", "SHA-256"),

    // ECDSA on the P-256 Curve(secp256r1) with a SHA-256 digest
    ECDSA_P256_SHA_256("EC_P256", "ECDSA_SHA_256", "SHA-256"),

    // ECDSA on the P-256K Curve(secp256k1) with a SHA-256 digest
    ECDSA_P256K_SHA_256("EC_P256K", "ECDSA_SHA_256", "SHA-256"),

    // SM2椭圆曲线数字签名算法
    SM2DSA("EC_SM2", "SM2DSA", "SM3");

    private final String keySpec;
    private final String algorithm;
    private final String digestAlgorithm;

    SignatureAlgorithm(String keySpec, String algorithm, String digestAlgorithm) {
        this.keySpec = keySpec;
        this.algorithm = algorithm;
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getKeySpec() {
        return this.keySpec;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getDigestAlgorithm() {
        return this.digestAlgorithm;
    }
}
