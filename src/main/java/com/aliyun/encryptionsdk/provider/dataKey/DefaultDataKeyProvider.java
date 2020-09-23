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

import com.aliyun.encryptionsdk.model.CipherMaterial;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;

/**
 * {@link BaseDataKeyProvider} 的一个实现，所有加密信息都保存在密文中
 */
public class DefaultDataKeyProvider extends BaseDataKeyProvider {


    public DefaultDataKeyProvider(String keyId) {
        super(keyId);
    }

    public DefaultDataKeyProvider(String keyId, CryptoAlgorithm algorithm) {
        super(keyId, algorithm);
    }

    @Override
    public CipherMaterial getCipherMaterial(byte[] cipherText) {
        return handler.deserialize(cipherText);
    }

    @Override
    public byte[] processCipherMaterial(CipherMaterial cipherMaterial) {
        return handler.serialize(cipherMaterial);
    }
}
