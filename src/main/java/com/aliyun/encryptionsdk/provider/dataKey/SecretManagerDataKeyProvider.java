/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aliyun.encryptionsdk.provider.dataKey;

import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.kms.AliyunKms;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.CipherHeader;
import com.aliyun.encryptionsdk.model.Constants;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.model.EncryptionMaterial;
import com.aliyuncs.exceptions.ClientException;

import java.util.Base64;
import java.util.UUID;

/**
 * {@link AbstractExternalStoreDataKeyProvider} 的SecretManager实现
 * {@code dataKeyName} 将作为secretName标识一个数据密钥
 */
public class SecretManagerDataKeyProvider extends AbstractExternalStoreDataKeyProvider {
    private static final String SECRET_DATA_TYPE_TEXT = "text";

    public SecretManagerDataKeyProvider(String keyId, String dataKeyName) {
        super(keyId, dataKeyName);
    }

    public SecretManagerDataKeyProvider(String keyId, CryptoAlgorithm algorithm, String dataKeyName) {
        super(keyId, algorithm, dataKeyName);
    }


    @Override
    public EncryptionMaterial encryptDataKey(EncryptionMaterial material) {
        CipherHeader cipherHeader = getCipherHeader(dataKeyName);
        if (cipherHeader != null) {
            return getEncryptionMaterial(cipherHeader, material);
        }

        EncryptionMaterial newMaterial = super.encryptDataKey(material);
        cipherHeader = new CipherHeader(newMaterial.getEncryptedDataKeys(),
                newMaterial.getEncryptionContext(), newMaterial.getAlgorithm());
        calculateHeaderAuthTag(newMaterial, cipherHeader);
        try {
            storeCipherHeader(dataKeyName, cipherHeader);
        } catch (Exception e) {
            if (e.getCause() instanceof ClientException) {
                ClientException exception = (ClientException) e.getCause();
                if ("Rejected.ResourceExist".equals(exception.getErrCode())) {
                    //若因为secretName已经存在的问题报错，则直接重新查询secretValue，可能有其他线程或分布式机器已经创建该secret了
                    cipherHeader = getCipherHeader(dataKeyName);
                    if (cipherHeader != null) {
                        return getEncryptionMaterial(cipherHeader, material);
                    } else {
                        CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("The cause of the error was ResourceExist, but the obtained dataKey is empty", e);
                        throw new AliyunException("The cause of the error was ResourceExist, but the obtained dataKey is empty", e);
                    }
                }
            }
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Failed to save dataKey to secretManager", e);
            throw e;
        }
        return newMaterial;
    }

    protected CipherHeader getCipherHeader(String dataKeyName) {
        try {
            AliyunKms.GetSecretValueResult result = kms.getSecretValue(keyId, dataKeyName);
            if (SECRET_DATA_TYPE_TEXT.equals(result.getSecretDataType())) {
                String base64Header = result.getSecretData();
                byte[] header = Base64.getDecoder().decode(base64Header);
                return handler.deserializeCipherHeader(header);
            } else {
                throw new AliyunException("Unprocessed case where secretDataType is binary");
            }
        } catch (Exception e) {
            //判断不同的异常做不同处理，若没有对应的Secret则返回null
            if (e.getCause() instanceof ClientException) {
                ClientException exception = (ClientException) e.getCause();
                if ("Forbidden.ResourceNotFound".equals(exception.getErrCode()) || "Forbidden.KeyNotFound".equals(exception.getErrCode())) {
                    return null;
                }
            }
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Failed to get dataKey from secretManager", e);
            throw e;
        }
    }

    private void storeCipherHeader(String dataKeyName, CipherHeader cipherHeader) {
        byte[] header = handler.serializeCipherHeader(cipherHeader);
        String base64Header = Base64.getEncoder().encodeToString(header);
        String versionId = UUID.randomUUID().toString();
        kms.createSecret(keyId, dataKeyName, versionId, base64Header, SECRET_DATA_TYPE_TEXT);
    }
}
