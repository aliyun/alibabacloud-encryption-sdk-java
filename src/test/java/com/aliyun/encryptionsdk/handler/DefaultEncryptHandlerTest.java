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

import com.aliyun.encryptionsdk.ckm.DefaultCryptoKeyManager;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.Test;


import static org.junit.Assert.assertArrayEquals;

public class DefaultEncryptHandlerTest {
    private static final String PLAIN_TEXT = "this is test.";
    private static final DefaultEncryptHandler ENCRYPT_HANDLER = new DefaultEncryptHandler();
    @Test
    public void testEncryptDecrypt() {
        EncryptionMaterial encryptDataKeyMaterial = TestFixtures.createMaterialsResult(1);
        CipherMaterial encryptResult = ENCRYPT_HANDLER.encrypt(PLAIN_TEXT.getBytes(), encryptDataKeyMaterial);

        DecryptionMaterial decryptionMaterial = new DefaultCryptoKeyManager().getDecryptDataKeyMaterial(TestFixtures.createDefaultDataKeyProvider(),
                encryptDataKeyMaterial.getEncryptionContext(), encryptDataKeyMaterial.getEncryptedDataKeys());
        byte[] decryptResultBytes = ENCRYPT_HANDLER.decrypt(encryptResult, decryptionMaterial);
        assertArrayEquals(PLAIN_TEXT.getBytes(), decryptResultBytes);
    }
}
