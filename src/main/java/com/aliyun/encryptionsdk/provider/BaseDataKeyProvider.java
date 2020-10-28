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

package com.aliyun.encryptionsdk.provider;

import com.aliyun.encryptionsdk.handler.Asn1FormatHandler;
import com.aliyun.encryptionsdk.handler.FormatHandler;
import com.aliyun.encryptionsdk.kms.AliyunKms;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.dataKey.AbstractExternalStoreDataKeyProvider;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * 数据密钥生成抽象类，提供对数据密钥处理方法
 */
public abstract class BaseDataKeyProvider {
    protected CryptoAlgorithm algorithm;
    protected FormatHandler handler;
    protected AliyunKms kms;
    protected CmkId keyId;
    private List<CmkId> keyIds = new ArrayList<>();

    public BaseDataKeyProvider(String keyId) {
        this(keyId, CryptoAlgorithm.AES_GCM_NOPADDING_256);
    }

    public BaseDataKeyProvider(String keyId, CryptoAlgorithm algorithm) {
        this.keyId = new CmkId(keyId);
        this.algorithm = algorithm;
        this.handler = new Asn1FormatHandler();
    }

    public void setAliyunKms(AliyunKms kms) {
        if (this.kms == null) {
            this.kms = kms;
        }
    }

    public void setMultiCmkId(List<String> keyIds) {
        List<CmkId> keyList = new ArrayList<>();
        if (keyIds != null && !keyIds.isEmpty()) {
            keyIds.remove(this.keyId.getKeyId());
            for (String keyId : keyIds) {
                keyList.add(new CmkId(keyId));
            }
        }
        this.keyIds = keyList;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(CryptoAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public void setFormatHandler(FormatHandler handler) {
        this.handler = handler;
    }

    /**
     * 生成一个数据密钥并进行加密处理
     * @param material 加密密钥材料（不包含获取数据密钥）
     * @return 加密密钥材料
     */
    public EncryptionMaterial encryptDataKey(EncryptionMaterial material) {
        EncryptionMaterial newMaterial = generateDataKey(material);

        EncryptedDataKey dataKey = newMaterial.getEncryptedDataKeys().get(0);
        for (CmkId key: keyIds) {
            if (keyId.isCommonRegion(key)) {
                //同region的CMK使用密文进行转加密
                newMaterial = reEncryptDataKey(key, dataKey, newMaterial);
            } else {
                newMaterial = encryptDataKey(key, newMaterial);
            }
        }
        return newMaterial;
    }

    /**
     * 解密数据密钥
     * @param material 解密密钥材料（不包含数据密钥明文）
     * @param encryptedDataKeys 数据密钥明文列表
     * @return 加密密钥材料
     */
    public DecryptionMaterial decryptDataKey(DecryptionMaterial material, List<EncryptedDataKey> encryptedDataKeys) {
        List<CmkId> keyIdList = new ArrayList<>(keyIds);
        if (keyId != null) {
            keyIdList.add(keyId);
        }

        for (EncryptedDataKey encryptedDataKey: encryptedDataKeys) {
            if (keyIdList.contains(new CmkId(encryptedDataKey.getKeyIdString()))) {
                try {
                    return decryptDataKey(material, encryptedDataKey);
                } catch (Exception e) {
                    continue;
                }
            }
        }
        return null;
    }

    /**
     * 通过密文或数据密钥关键字获取数据密钥并生成密码材料
     * @param cipherText 密文
     * @return 密码材料
     */
    public abstract CipherMaterial getCipherMaterial(byte[] cipherText);

    /**
     * 处理密码材料生成字节数组，字节数组内容可能包含：
     * 1.{@link CipherMaterial} 的所有内容
     * 2.{@link CipherMaterial} 中的 {@link CipherBody} 部分（{@link CipherHeader} 部分由
     * {@link AbstractExternalStoreDataKeyProvider} 的实现自行处理）
     * @param cipherMaterial 密码材料
     * @return 加密结果
     */
    public abstract byte[] processCipherMaterial(CipherMaterial cipherMaterial);

    private EncryptionMaterial generateDataKey(EncryptionMaterial material) {
        AliyunKms.GenerateDataKeyResult result = kms.generateDataKey(keyId, material.getAlgorithm(), material.getEncryptionContext());

        byte[] plainText = Base64.getDecoder().decode(result.getPlaintext());
        material.setPlaintextDataKey(new SecretKeySpec(plainText, material.getAlgorithm().getKeyName()));
        material.addEncryptedDataKeys(result.getEncryptedDataKey());
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("[keyId: %s] generate and encrypt a dataKey", keyId.getKeyId()));
        return material;
    }

    private EncryptionMaterial encryptDataKey(CmkId keyId, EncryptionMaterial material) {
        EncryptedDataKey result = kms.encryptDataKey(keyId, Base64.getEncoder().encodeToString(material.getPlaintextDataKey().getEncoded()), material.getEncryptionContext());
        material.addEncryptedDataKeys(result);
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("[keyId: %s] encrypt a dataKey generated by [keyId: %s]", keyId.getKeyId(), this.keyId.getKeyId()));
        return material;
    }

    private EncryptionMaterial reEncryptDataKey(CmkId keyId, EncryptedDataKey dataKey, EncryptionMaterial material) {
        EncryptedDataKey result = kms.reEncryptDataKey(keyId, dataKey, material.getEncryptionContext());
        material.addEncryptedDataKeys(result);
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("[keyId: %s] encrypt a dataKey generated by [keyId: %s]", keyId.getKeyId(), this.keyId.getKeyId()));
        return material;
    }

    private DecryptionMaterial decryptDataKey(DecryptionMaterial material, EncryptedDataKey encryptedDataKey) {
        AliyunKms.DecryptDataKeyResult result = kms.decryptDataKey(encryptedDataKey, material.getEncryptionContext());

        byte[] plainText = Base64.getDecoder().decode(result.getPlaintext());
        material.setPlaintextDataKey(new SecretKeySpec(plainText, material.getAlgorithm().getKeyName()));
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("[keyId: %s] decrypt a dataKey", encryptedDataKey.getKeyIdString()));
        return material;
    }
}
