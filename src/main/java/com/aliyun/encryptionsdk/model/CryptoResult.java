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

import java.util.List;
import java.util.Map;

public class CryptoResult<T> {
    private T result;
    private CipherMaterial cipherMaterial;

    public CryptoResult(T result, CipherMaterial cipherMaterial) {
        this.result = result;
        this.cipherMaterial = cipherMaterial;
    }

    public T getResult() {
        return result;
    }

    public CryptoAlgorithm getAlgorithm() {
        return cipherMaterial.getCipherHeader().getAlgorithm();
    }

    public Map<String, String> getEncryptionContext() {
        return cipherMaterial.getCipherHeader().getEncryptionContext();
    }

    public List<EncryptedDataKey> getEncryptedDataKeyList() {
        return cipherMaterial.getCipherHeader().getEncryptedDataKeys();
    }

    public CipherMaterial getCipherMaterial() {
        return cipherMaterial;
    }
}
