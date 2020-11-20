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

import javax.crypto.SecretKey;
import java.util.*;

public class EncryptionMaterial {
    private int version = Constants.SDK_VERSION;
    private SecretKey plaintextDataKey;
    private List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
    private Map<String, String> encryptionContext = new HashMap<>();
    private CryptoAlgorithm algorithm;

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public SecretKey getPlaintextDataKey() {
        return plaintextDataKey;
    }

    public void setPlaintextDataKey(SecretKey plaintextDataKey) {
        this.plaintextDataKey = plaintextDataKey;
    }

    public List<EncryptedDataKey> getEncryptedDataKeys() {
        return encryptedDataKeys;
    }

    public void setEncryptedDataKeys(List<EncryptedDataKey> encryptedDataKeys) {
        this.encryptedDataKeys = encryptedDataKeys;
    }

    public void addEncryptedDataKeys(EncryptedDataKey encryptedDataKey) {
        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(this.encryptedDataKeys);
        encryptedDataKeys.add(encryptedDataKey);
        this.encryptedDataKeys = encryptedDataKeys;
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public void setEncryptionContext(Map<String, String> encryptionContext) {
        this.encryptionContext = encryptionContext;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(CryptoAlgorithm algorithm) {
        this.algorithm = algorithm;
    }
}
