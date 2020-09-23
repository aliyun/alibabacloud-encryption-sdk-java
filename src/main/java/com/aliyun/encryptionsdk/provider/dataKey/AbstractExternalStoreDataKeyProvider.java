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

package com.aliyun.encryptionsdk.provider.dataKey;

import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.handler.AlgorithmHandler;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;

import javax.crypto.Cipher;
import java.util.List;

/**
 * {@link BaseDataKeyProvider} 的一个外部保存 {@link CipherHeader} 抽象实现，
 * 密文中仅保存 {@link CipherBody} 部分
 */
public abstract class AbstractExternalStoreDataKeyProvider extends BaseDataKeyProvider {
    protected String dataKeyName;

    public AbstractExternalStoreDataKeyProvider(String keyId, String dataKeyName) {
        super(keyId);
        this.dataKeyName = dataKeyName;
    }

    public AbstractExternalStoreDataKeyProvider(String keyId, CryptoAlgorithm algorithm, String dataKeyName) {
        super(keyId, algorithm);
        this.dataKeyName = dataKeyName;
    }


    @Override
    public DecryptionMaterial decryptDataKey(DecryptionMaterial material, List<EncryptedDataKey> encryptedDataKeys) {
        return super.decryptDataKey(material, encryptedDataKeys);
    }

    @Override
    public CipherMaterial getCipherMaterial(byte[] cipherText) {
        CipherBody cipherBody = getCipherBody(cipherText);
        CipherHeader cipherHeader;
        try {
            cipherHeader = getCipherHeader(dataKeyName);
            if (cipherHeader == null) {
                throw new AliyunException("cipherHeader not obtained");
            }
        } catch (Exception e) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Can't get dataKey from external", e);
            throw new AliyunException("Can't get dataKey from external", e);
        }
        return new CipherMaterial(cipherHeader, cipherBody);
    }

    @Override
    public byte[] processCipherMaterial(CipherMaterial cipherMaterial) {
        return handler.serializeCipherBody(cipherMaterial.getCipherBody());
    }

    EncryptionMaterial getEncryptionMaterial(CipherHeader cipherHeader, EncryptionMaterial material) {
        DecryptionMaterial decryptionMaterial = new DecryptionMaterial();
        decryptionMaterial.setAlgorithm(cipherHeader.getAlgorithm());
        decryptionMaterial.setEncryptionContext(cipherHeader.getEncryptionContext());

        decryptionMaterial = decryptDataKey(decryptionMaterial, cipherHeader.getEncryptedDataKeys());
        material.setPlaintextDataKey(decryptionMaterial.getPlaintextDataKey());
        material.setEncryptedDataKeys(cipherHeader.getEncryptedDataKeys());
        return material;
    }

    protected abstract CipherHeader getCipherHeader(String dataKeyName);

    private CipherBody getCipherBody(byte[] cipherText) {
        return handler.deserializeCipherBody(cipherText);
    }

    protected void calculateHeaderAuthTag(EncryptionMaterial newMaterial, CipherHeader cipherHeader) {
        AlgorithmHandler handler = new AlgorithmHandler(newMaterial.getAlgorithm(), newMaterial.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        cipherHeader.calculateHeaderAuthTag(handler);
    }
}
