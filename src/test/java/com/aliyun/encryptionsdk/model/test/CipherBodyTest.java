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

package com.aliyun.encryptionsdk.model.test;


import com.aliyun.encryptionsdk.handler.AlgorithmHandler;
import com.aliyun.encryptionsdk.model.CipherBody;
import com.aliyun.encryptionsdk.model.EncryptionMaterial;
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;


public class CipherBodyTest {
    private static final String PLAIN_TEXT = "this is test.";
    @Test
    public void testBuilder(){
        EncryptionMaterial encryptionMaterial = TestFixtures.createMaterialsResult(1);
        AlgorithmHandler handler = new AlgorithmHandler(encryptionMaterial.getAlgorithm(), encryptionMaterial.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        byte[] iv = new byte[encryptionMaterial.getAlgorithm().getIvLen()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        byte[] contentAad = null;
        if (encryptionMaterial.getAlgorithm().isWithAad()) {
            contentAad = TestFixtures.serializeContext(encryptionMaterial.getEncryptionContext());
        }
        byte[] result = handler.cipherData(iv, contentAad, PLAIN_TEXT.getBytes(), 0, PLAIN_TEXT.length());

        int tagLen = encryptionMaterial.getAlgorithm().getTagLen();
        byte[] cipherText = new byte[result.length - tagLen];
        byte[] authTag = new byte[tagLen];
        if (tagLen != 0) {
            System.arraycopy(result, 0, cipherText, 0, result.length - tagLen);
            System.arraycopy(result, cipherText.length, authTag, 0, tagLen);
        } else {
            cipherText = result;
        }

        CipherBody cipherBody = new CipherBody(iv, cipherText, authTag);

        assertArrayEquals(cipherText, cipherBody.getCipherText());
        assertArrayEquals(iv, cipherBody.getIv());
        assertArrayEquals(authTag, cipherBody.getAuthTag());
    }
}
