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

package com.aliyun.encryptionsdk.handler;

import com.aliyun.encryptionsdk.model.*;

import javax.crypto.Cipher;
import java.security.SecureRandom;

/**
 * {@link EncryptHandler} 的默认实现
 */
public class DefaultEncryptHandler implements EncryptHandler {

    @Override
    public CipherMaterial encrypt(byte[] plaintext, EncryptionMaterial encryptionMaterial) {
        AlgorithmHandler handler = new AlgorithmHandler(encryptionMaterial.getAlgorithm(), encryptionMaterial.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        CipherHeader cipherHeader = new CipherHeader(encryptionMaterial.getEncryptedDataKeys(),
                encryptionMaterial.getEncryptionContext(), encryptionMaterial.getAlgorithm());
        cipherHeader.calculateHeaderAuthTag(handler);

        byte[] iv = randomIv(encryptionMaterial.getAlgorithm().getIvLen());
        byte[] context = null;
        if (cipherHeader.getAlgorithm().isWithAad()) {
            context = cipherHeader.getEncryptionContextBytes();
        }
        byte[] cipherResult = handler.cipherData(iv, context, plaintext, 0, plaintext.length);

        int tagLen = cipherHeader.getAlgorithm().getTagLen();
        byte[] cipherText = new byte[cipherResult.length - tagLen];
        byte[] authTag = new byte[tagLen];
        if (tagLen != 0) {
            System.arraycopy(cipherResult, 0, cipherText, 0, cipherResult.length - tagLen);
            System.arraycopy(cipherResult, cipherText.length, authTag, 0, tagLen);
        } else {
            cipherText = cipherResult;
        }
        CipherBody cipherBody = new CipherBody(iv, cipherText, authTag);
        return new CipherMaterial(cipherHeader, cipherBody);
    }

    private byte[] randomIv(int len) {
        byte[] iv = new byte[len];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    @Override
    public byte[] decrypt(CipherMaterial cipherMaterial, DecryptionMaterial decryptionMaterial) {
        AlgorithmHandler handler = new AlgorithmHandler(decryptionMaterial.getAlgorithm(), decryptionMaterial.getPlaintextDataKey(), Cipher.DECRYPT_MODE);
        verifyHeaderAuthTag(cipherMaterial.getCipherHeader(), handler);

        CipherBody cipherBody = cipherMaterial.getCipherBody();
        byte[] cipherText = cipherBody.getCipherText();
        byte[] authTag = cipherBody.getAuthTag();
        if (authTag.length != cipherMaterial.getCipherHeader().getAlgorithm().getTagLen()) {
            throw new IllegalArgumentException("Invalid tag length: " + authTag.length);
        }
        byte[] result = new byte[cipherText.length + authTag.length];
        System.arraycopy(cipherText, 0, result, 0, cipherText.length);
        System.arraycopy(authTag, 0, result, cipherText.length, authTag.length);

        return handler.cipherData(cipherBody.getIv(), cipherMaterial.getCipherHeader().getEncryptionContextBytes(),
                result, 0, result.length);
    }

    private void verifyHeaderAuthTag(CipherHeader cipherHeader, AlgorithmHandler handler) {
        byte[] headerAuthTag = cipherHeader.getHeaderAuthTag();
        handler.cipherData(cipherHeader.getHeaderIv(), cipherHeader.serializeAuthenticatedFields(), headerAuthTag, 0, headerAuthTag.length);
    }
}
