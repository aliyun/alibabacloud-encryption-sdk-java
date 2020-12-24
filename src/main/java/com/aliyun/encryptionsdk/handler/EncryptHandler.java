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

import com.aliyun.encryptionsdk.model.CipherMaterial;
import com.aliyun.encryptionsdk.model.DecryptionMaterial;
import com.aliyun.encryptionsdk.model.EncryptionMaterial;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * 定义数据的加解密方法
 */
public interface EncryptHandler {

    /**
     * 对一个明文字节数组进行加密
     * @param plaintext 明文字节数组
     * @param encryptionMaterial 加密密钥材料
     * @return 加密结果（包括加密的材料和密文）
     */
    CipherMaterial encrypt(byte[] plaintext, EncryptionMaterial encryptionMaterial);

    /**
     * 对一个加密结果进行解密
     * @param cipherMaterial 加密结果
     * @param decryptionMaterial 解密密钥材料
     * @return 明文字节数组
     */
    byte[] decrypt(CipherMaterial cipherMaterial, DecryptionMaterial decryptionMaterial);

    /**
     * 对 {@link InputStream} 输入流进行加密，并将加密结果写入 {@link OutputStream}
     * @param inputStream 待加密流
     * @param outputStream 已加密流
     * @param provider 数据密钥提供
     * @param encryptionMaterial 加密材料
     * @return 加密结果
     */
    CipherMaterial encryptStream(InputStream inputStream, OutputStream outputStream, BaseDataKeyProvider provider, EncryptionMaterial encryptionMaterial);

    /**
     * 对 {@link InputStream} 输入流进行解密，并将解密结果写入 {@link OutputStream}
     * @param inputStream 加密流
     * @param outputStream 已解密流
     * @param cipherMaterial 加密信息
     * @param decryptionMaterial 解密材料
     */
    void decryptStream(InputStream inputStream, OutputStream outputStream, CipherMaterial cipherMaterial, DecryptionMaterial decryptionMaterial);
}
