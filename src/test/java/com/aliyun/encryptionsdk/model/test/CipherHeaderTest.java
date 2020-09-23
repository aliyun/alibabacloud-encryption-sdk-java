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

import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.jupiter.api.Test;


public class CipherHeaderTest {
    private static final CryptoAlgorithm ALGORITHM = CryptoAlgorithm.AES_GCM_NOPADDING_256;
    @Test
    public void testBuilder(){

        EncryptionMaterial encryptionMaterial = TestFixtures.createMaterialsResult(1);

        CipherHeader cipherHeader = new CipherHeader(encryptionMaterial.getEncryptedDataKeys(), encryptionMaterial.getEncryptionContext(), encryptionMaterial.getAlgorithm());

        TestFixtures.assertEncryptedDataKeysEquals(encryptionMaterial.getEncryptedDataKeys(), cipherHeader.getEncryptedDataKeys());
        TestFixtures.assertEncryptionContextEquals(encryptionMaterial.getEncryptionContext(), cipherHeader.getEncryptionContext());
        TestFixtures.assertEncryptionAlgorithmEquals(ALGORITHM, cipherHeader.getAlgorithm());
    }
}
