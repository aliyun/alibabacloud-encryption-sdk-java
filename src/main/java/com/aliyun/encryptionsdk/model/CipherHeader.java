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

import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.handler.AlgorithmHandler;

import java.security.SecureRandom;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class CipherHeader {
    private CryptoAlgorithm algorithm;
    private Map<String, String> encryptionContext;
    private byte[] encryptionContextBytes;
    private List<EncryptedDataKey> encryptedDataKeys;
    private byte[] headerIv;
    private byte[] headerAuthTag;

    public CipherHeader(List<EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext, CryptoAlgorithm algorithm) {
        this.encryptedDataKeys = encryptedDataKeys;
        this.encryptionContext = encryptionContext;
        this.encryptionContextBytes = serializeContext(encryptionContext);
        this.algorithm = algorithm;
    }

    public CipherHeader(List<EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext, CryptoAlgorithm algorithm,
                        byte[] headerIv, byte[] headerAuthTag) {
        this.encryptedDataKeys = encryptedDataKeys;
        this.encryptionContext = encryptionContext;
        this.encryptionContextBytes = serializeContext(encryptionContext);
        this.algorithm = algorithm;
        this.headerIv = headerIv;
        this.headerAuthTag = headerAuthTag;
    }

    public void setHeaderIv(byte[] headerIv) {
        this.headerIv = headerIv;
    }

    public void setAlgorithm(CryptoAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public List<EncryptedDataKey> getEncryptedDataKeys() {
        return encryptedDataKeys;
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public byte[] getEncryptionContextBytes() {
        return encryptionContextBytes;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public byte[] getHeaderIv() {
        return headerIv;
    }

    public byte[] getHeaderAuthTag() {
        return headerAuthTag;
    }

    public void calculateHeaderAuthTag(AlgorithmHandler handler) {
        byte[] headerFieldsBytes = serializeAuthenticatedFields();
        byte[] headerIv = new byte[algorithm.getIvLen()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(headerIv);
        byte[] headerAuthTag = handler.headerGcmEncrypt(headerIv, headerFieldsBytes, new byte[0], 0, 0);
        this.headerIv = headerIv;
        this.headerAuthTag = headerAuthTag;
    }

    public byte[] serializeAuthenticatedFields() {
        try {
            ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outBytes);

            dataStream.writeInt(algorithm.getValue());
            dataStream.writeInt(encryptionContext.size());
            dataStream.write(encryptionContextBytes);

            dataStream.writeInt(encryptedDataKeys.size());
            TreeSet<EncryptedDataKey> set = new TreeSet<>(encryptedDataKeys);
            for (EncryptedDataKey dataKey: set) {
                dataStream.write(dataKey.toByteArray());
            }
            dataStream.close();
            return outBytes.toByteArray();
        } catch (IOException e) {
            throw new AliyunException("Failed to serialize cipher text headers", e);
        }
    }

    private byte[] serializeContext(Map<String, String> encryptionContext) {
        TreeMap<String, String> map = new TreeMap<>(encryptionContext);
        ByteBuffer result = ByteBuffer.allocate(Short.MAX_VALUE);
        result.order(ByteOrder.BIG_ENDIAN);
        result.putInt(encryptionContext.size());
        try {
            for (Map.Entry<String, String> mapEntry: map.entrySet()) {
                byte[] keyBytes = mapEntry.getKey().getBytes(StandardCharsets.UTF_8);
                result.putInt(keyBytes.length);
                result.put(keyBytes);
                byte[] valueBytes = mapEntry.getValue().getBytes(StandardCharsets.UTF_8);
                result.putInt(valueBytes.length);
                result.put(valueBytes);
            }
        } catch (BufferUnderflowException e) {
            throw new AliyunException("encryptionContext must be shorter than " + Short.MAX_VALUE, e);
        }
        result.flip();
        byte[] encryptionContextBytes = new byte[result.limit()];
        result.get(encryptionContextBytes);
        return encryptionContextBytes;
    }
}
