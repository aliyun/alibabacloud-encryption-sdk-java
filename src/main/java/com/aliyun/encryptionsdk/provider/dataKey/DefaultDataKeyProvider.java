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

import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.model.CipherBody;
import com.aliyun.encryptionsdk.model.CipherHeader;
import com.aliyun.encryptionsdk.model.CipherMaterial;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.stream.CopyStreamUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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
    public CipherMaterial getCipherMaterial(InputStream inputStream) {
        try {
            CipherHeader cipherHeader = new CipherHeader();
            cipherHeader.deserialize(inputStream);
            byte[] ivLen = new byte[4];
            inputStream.read(ivLen);
            byte[] iv = new byte[CopyStreamUtil.bytesToInt(ivLen)];
            inputStream.read(iv);
            CipherBody cipherBody = new CipherBody(iv, null);
            return new CipherMaterial(cipherHeader, cipherBody);
        } catch (IOException e) {
            throw new AliyunException("Failed to get CipherMaterial from InputStream", e);
        }
    }

    @Override
    public byte[] processCipherMaterial(CipherMaterial cipherMaterial) {
        return handler.serialize(cipherMaterial);
    }

    @Override
    public void writeCipherHeader(CipherHeader cipherHeader, OutputStream outputStream) {
        byte[] serializeBytes = cipherHeader.serialize();
        try {
            outputStream.write(serializeBytes);
            outputStream.flush();
        } catch (IOException e) {
            throw new AliyunException("Failed to write CipherHeader to OutputStream", e);
        }
    }
}
