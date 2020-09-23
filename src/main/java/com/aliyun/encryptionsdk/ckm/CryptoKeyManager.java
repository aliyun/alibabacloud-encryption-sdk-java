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

import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * 密钥材料管理器，处理请求所需要的密钥材料
 *
 * @see EncryptionMaterial 加密材料
 * @see DecryptionMaterial 解密材料
 * @see SignatureMaterial 加签材料
 * @see VerifyMaterial 验签材料
 */
public interface CryptoKeyManager {
    Charset ENCODING = StandardCharsets.UTF_8;

    EncryptionMaterial getEncryptDataKeyMaterial(BaseDataKeyProvider provider, Map<String, String> encryptionContext, long plaintextSize);

    DecryptionMaterial getDecryptDataKeyMaterial(BaseDataKeyProvider provider, Map<String, String> encryptionContext, List<EncryptedDataKey> encryptedDataKeys);

    SignatureMaterial getSignatureMaterial(SignatureProvider provider, byte[] content, ContentType type);

    VerifyMaterial getVerifyMaterial(SignatureProvider provider, byte[] content, byte[] signature, ContentType type);
}
