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

package com.aliyun.encryptionsdk.kms;

import com.aliyun.encryptionsdk.model.CmkId;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.model.EncryptedDataKey;
import com.aliyun.encryptionsdk.model.SignatureAlgorithm;

import java.util.Map;

/**
 * 定义了请求kms服务端的接口
 */
public interface AliyunKms {

    /**
     * 使用主密钥生成一个数据密钥
     * @param keyId keyId
     * @param algorithm 算法信息
     * @param context dataKey密钥上下文信息，后续解密对应的dataKey需要相同的上下文信息
     * @return 返回包含数据密钥明文（Base64编码）和经过keyId对应的主密钥加密后的数据密钥密文
     */
    GenerateDataKeyResult generateDataKey(CmkId keyId, CryptoAlgorithm algorithm, Map<String, String> context);

    /**
     * 解密一个数据密钥密文
     * @param encryptedDataKey 数据密钥密文
     * @param context dataKey密钥上下文信息
     * @return 数据密钥明文（Base64编码）
     */
    DecryptDataKeyResult decryptDataKey(EncryptedDataKey encryptedDataKey, Map<String, String> context);

    /**
     * 加密一个数据密文明文
     * @param keyId keyId
     * @param plaintext 数据密钥明文（Base64编码）
     * @param context dataKey密钥上下文信息
     * @return 数据密钥密文
     */
    EncryptedDataKey encryptDataKey(CmkId keyId, String plaintext, Map<String, String> context);

    /**
     * 转加密一个数据密钥密文
     * @param keyId 待加密的keyId
     * @param encryptedDataKey 数据密钥密文
     * @param context dataKey密钥上下文信息
     * @return 数据密钥密文（内部为待加密的keyId对应的主密钥加密后的数据密钥密文）
     */
    EncryptedDataKey reEncryptDataKey(CmkId keyId, EncryptedDataKey encryptedDataKey, Map<String, String> context);

    /**
     * 使用非对称密钥进行签名
     * @param keyId keyId
     * @param keyVersionId keyId对应主密钥的版本
     * @param algorithm 非对称算法
     * @param message 签名信息
     * @return 计算出来的签名结果（Base64编码）
     */
    AsymmetricSignResult asymmetricSign(CmkId keyId, String keyVersionId, SignatureAlgorithm algorithm, byte[] message);

    /**
     * 使用非对称密钥进行验签
     * @param keyId keyId
     * @param keyVersionId keyId对应主密钥的版本
     * @param algorithm 非对称算法
     * @param message 使用Algorithm中对应的哈希算法，对原始message生成的摘要
     * @param signature 待验证的签名结果
     * @return 验签结果
     */
    AsymmetricVerifyResult asymmetricVerify(CmkId keyId, String keyVersionId, SignatureAlgorithm algorithm, byte[] message, byte[] signature);

    /**
     * 获取非对称密钥的公钥。用户可以在本地使用公钥进行加密、验签。
     * @param keyId keyId
     * @param keyVersionId keyId对应主密钥的版本
     * @return 公钥
     */
    String getPublicKey(CmkId keyId, String keyVersionId);

    /**
     * 使用主密钥创建一个凭据，以及凭据的初始版本
     * @param keyId keyId
     * @param secretName 凭据名称
     * @param versionId 凭据初始版本
     * @param secretData 凭据值
     * @param secretDataType 凭据值的类型
     * @return CreateSecretResult
     */
    CreateSecretResult createSecret(CmkId keyId, String secretName, String versionId, String secretData, String secretDataType);

    /**
     * 获取被凭据保护的凭据值内容
     * @param keyId keyId
     * @param secretName 凭据名称
     * @return 凭据值和凭据值的类型
     */
    GetSecretValueResult getSecretValue(CmkId keyId, String secretName);

    class BaseResult {
        private String keyId;
        private String keyVersionId;

        public BaseResult(String keyId, String keyVersionId) {
            this.keyId = keyId;
            this.keyVersionId = keyVersionId;
        }

        public String getKeyId() {
            return keyId;
        }

        public String getKeyVersionId() {
            return keyVersionId;
        }
    }

    class GenerateDataKeyResult extends BaseResult {
        private String plaintext;
        private EncryptedDataKey encryptedDataKey;

        public GenerateDataKeyResult(String keyId, String keyVersionId, String plaintext, String cipherTextBlob) {
            super(keyId, keyVersionId);
            this.plaintext = plaintext;
            this.encryptedDataKey = new EncryptedDataKey(keyId, cipherTextBlob);
        }

        public String getPlaintext() {
            return plaintext;
        }

        public EncryptedDataKey getEncryptedDataKey() {
            return encryptedDataKey;
        }
    }

    class DecryptDataKeyResult extends BaseResult {
        private String plaintext;

        public DecryptDataKeyResult(String keyId, String keyVersionId, String plaintext) {
            super(keyId, keyVersionId);
            this.plaintext = plaintext;
        }

        public String getPlaintext() {
            return plaintext;
        }
    }

    class AsymmetricSignResult extends BaseResult {
        private final String value;

        public AsymmetricSignResult(String keyId, String keyVersionId, String value) {
            super(keyId, keyVersionId);
            this.value = value;
        }

        public String getValue() {
            return this.value;
        }
    }

    class AsymmetricVerifyResult extends BaseResult {
        private final Boolean value;

        public AsymmetricVerifyResult(String keyId, String keyVersionId, Boolean value) {
            super(keyId, keyVersionId);
            this.value = value;
        }

        public Boolean getValue() {
            return value;
        }
    }

    class CreateSecretResult {
        private String arn;
        private String secretName;
        private String versionId;

        public CreateSecretResult(String arn, String secretName, String versionId) {
            this.arn = arn;
            this.secretName = secretName;
            this.versionId = versionId;
        }

        public String getArn() {
            return arn;
        }

        public String getSecretName() {
            return secretName;
        }

        public String getVersionId() {
            return versionId;
        }
    }

    class GetSecretValueResult {
        private String secretName;
        private String secretData;
        private String secretDataType;

        public GetSecretValueResult(String secretName, String secretData, String secretDataType) {
            this.secretName = secretName;
            this.secretData = secretData;
            this.secretDataType = secretDataType;
        }

        public String getSecretName() {
            return secretName;
        }

        public String getSecretData() {
            return secretData;
        }

        public String getSecretDataType() {
            return secretDataType;
        }
    }
}
