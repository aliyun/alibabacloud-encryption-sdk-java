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

package com.aliyun.encryptionsdk.ckm;

import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;

import java.util.List;
import java.util.Map;

/**
 * {@link CryptoKeyManager} 的默认实现，
 */
public class DefaultCryptoKeyManager implements CryptoKeyManager {

    @Override
    public EncryptionMaterial getEncryptDataKeyMaterial(BaseDataKeyProvider provider, Map<String, String> encryptionContext, long plaintextSize) {
        EncryptionMaterial material = new EncryptionMaterial();
        material.setEncryptionContext(encryptionContext);
        material.setAlgorithm(provider.getAlgorithm());

        return provider.encryptDataKey(material);
    }

    @Override
    public DecryptionMaterial getDecryptDataKeyMaterial(BaseDataKeyProvider provider, Map<String, String> encryptionContext, List<EncryptedDataKey> encryptedDataKeys) {
        DecryptionMaterial material = new DecryptionMaterial();
        material.setEncryptionContext(encryptionContext);
        material.setAlgorithm(provider.getAlgorithm());

        DecryptionMaterial result = provider.decryptDataKey(material, encryptedDataKeys);
        if (result == null) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Failed to get dataKey from encryptedDataKeys");
            throw new UnFoundDataKeyException("Failed to get dataKey from encryptedDataKeys");
        }
        return result;
    }

    @Override
    public SignatureMaterial getSignatureMaterial(SignatureProvider provider, byte[] content, ContentType type) {
        SignatureMaterial material = new SignatureMaterial();
        material.setSignatureAlgorithm(provider.getSignatureAlgorithm());
        if (type.equals(ContentType.DIGEST)) {
            material.setDigest(content);
        } else {
            material.setMessage(content);
        }
        return provider.sign(material);
    }

    @Override
    public VerifyMaterial getVerifyMaterial(SignatureProvider provider, byte[] content, byte[] signature, ContentType type) {
        VerifyMaterial material = new VerifyMaterial();
        material.setSignature(signature);
        material.setSignatureAlgorithm(provider.getSignatureAlgorithm());
        if (type.equals(ContentType.DIGEST)) {
            material.setDigest(content);
        } else {
            material.setMessage(content);
        }
        return provider.verify(material);
    }
}
