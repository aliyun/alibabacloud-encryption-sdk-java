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

import java.io.*;
import java.security.SecureRandom;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class CipherHeader {
    private int version;
    private CryptoAlgorithm algorithm;
    private Map<String, String> encryptionContext;
    private byte[] encryptionContextBytes;
    private List<EncryptedDataKey> encryptedDataKeys;
    private byte[] headerIv;
    private byte[] headerAuthTag;

    public static int HEADER_IV_LEN = 12;

    public CipherHeader(List<EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext, CryptoAlgorithm algorithm) {
        this.version = Constants.SDK_VERSION;
        this.encryptedDataKeys = encryptedDataKeys;
        this.encryptionContext = encryptionContext;
        serializeContext();
        this.algorithm = algorithm;
    }

    public CipherHeader(List<EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext, CryptoAlgorithm algorithm,
                        byte[] headerIv, byte[] headerAuthTag) {
        this.version = Constants.SDK_VERSION;
        this.encryptedDataKeys = encryptedDataKeys;
        this.encryptionContext = encryptionContext;
        serializeContext();
        this.algorithm = algorithm;
        this.headerIv = headerIv;
        this.headerAuthTag = headerAuthTag;
    }

    public CipherHeader(int version, List<EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext, CryptoAlgorithm algorithm) {
        this.version = version;
        this.encryptedDataKeys = encryptedDataKeys;
        this.encryptionContext = encryptionContext;
        serializeContext();
        this.algorithm = algorithm;
    }

    public CipherHeader(int version, List<EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext, CryptoAlgorithm algorithm,
                        byte[] headerIv, byte[] headerAuthTag) {
        this.version = version;
        this.encryptedDataKeys = encryptedDataKeys;
        this.encryptionContext = encryptionContext;
        serializeContext();
        this.algorithm = algorithm;
        this.headerIv = headerIv;
        this.headerAuthTag = headerAuthTag;
    }

    public CipherHeader() {

    }

    public void setVersion(int version) {
        this.version = version;
    }

    public int getVersion() {
        return this.version;
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
        byte[] headerIv = new byte[HEADER_IV_LEN];
        SecureRandom random = new SecureRandom();
        random.nextBytes(headerIv);
        byte[] headerAuthTag = handler.headerGcmEncrypt(headerIv, headerFieldsBytes, new byte[0], 0, 0);
        this.headerIv = headerIv;
        this.headerAuthTag = headerAuthTag;
    }

    public boolean verifyHeaderAuthTag(AlgorithmHandler handler) {
        try {
            byte[] headerAuthTagCalc = handler.headerGcmEncrypt(headerIv, serializeAuthenticatedFields(), new byte[0], 0, 0);
            if(headerAuthTagCalc == null) {
                return false;
            }
            if (Arrays.equals(headerAuthTag, headerAuthTagCalc)) {
                return true;
            } else {
                return false;
            }
        }catch(Exception e){
            return false;
        }
    }

    public byte[] serializeAuthenticatedFields() {
        try {
            ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outBytes);

            dataStream.writeInt(version);
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

    public byte[] serialize() {
        try {
            ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outBytes);

            dataStream.writeInt(version);
            dataStream.writeInt(algorithm.getValue());
            dataStream.writeInt(encryptionContextBytes.length);
            dataStream.write(encryptionContextBytes);

            dataStream.writeInt(encryptedDataKeys.size());
            TreeSet<EncryptedDataKey> set = new TreeSet<>(encryptedDataKeys);
            for (EncryptedDataKey dataKey: set) {
                dataStream.write(dataKey.toByteArray());
            }
            dataStream.writeInt(headerIv.length);
            dataStream.write(headerIv);
            dataStream.writeInt(headerAuthTag.length);
            dataStream.write(headerAuthTag);
            dataStream.close();
            return outBytes.toByteArray();
        } catch (IOException e) {
            throw new AliyunException("Failed to serialize cipher text headers", e);
        }
    }

    public void deserialize(InputStream inputStream) throws IOException {
        DataInputStream dataStream = new DataInputStream(inputStream);
        version = dataStream.readInt();
        algorithm = CryptoAlgorithm.getAlgorithm(dataStream.readInt());
        int encryptionContextBytesLen = dataStream.readInt();
        encryptionContextBytes = new byte[encryptionContextBytesLen];
        dataStream.read(encryptionContextBytes);
        deserializeContext();
        int dataKeySize = dataStream.readInt();
        encryptedDataKeys = new ArrayList<>();
        for (int i = 0; i < dataKeySize; i++) {
            int keyIdLen = dataStream.readInt();
            byte[] keyIdBytes = new byte[keyIdLen];
            dataStream.read(keyIdBytes);

            int dataKeyLen = dataStream.readInt();
            byte[] dataKeyBytes = new byte[dataKeyLen];
            dataStream.read(dataKeyBytes);
            encryptedDataKeys.add(new EncryptedDataKey(keyIdBytes, dataKeyBytes));
        }
        int headerIvLen = dataStream.readInt();
        headerIv = new byte[headerIvLen];
        dataStream.read(headerIv);
        int headerAuthTagLen = dataStream.readInt();
        headerAuthTag = new byte[headerAuthTagLen];
        dataStream.read(headerAuthTag);
    }


    private void serializeContext() {
        if (encryptionContext.size() == 0) {
            encryptionContextBytes = new byte[0];
            return;
        }
        TreeMap<String, String> map = new TreeMap<>((o1, o2) -> {
            // -1 升序 1 降序
            byte[] o1bytes = o1.getBytes(StandardCharsets.UTF_8);
            byte[] o2bytes = o2.getBytes(StandardCharsets.UTF_8);

            int len = Math.min(o1bytes.length, o2bytes.length);
            for (int i = 0; i < len; i++) {
                int b1 = o1bytes[i] & 0xFF;
                int b2 = o2bytes[i] & 0xFF;

                if (b1 != b2) {
                    return b1 - b2;
                }
            }
            return o1bytes.length - o2bytes.length;
        });
        map.putAll(encryptionContext);
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
        encryptionContextBytes = new byte[result.limit()];
        result.get(encryptionContextBytes);
    }

    private void deserializeContext() {
        if (encryptionContextBytes.length == 0) {
            encryptionContext = Collections.emptyMap();
            return;
        }
        ByteBuffer contextBytes = ByteBuffer.wrap(encryptionContextBytes);
        contextBytes.order(ByteOrder.BIG_ENDIAN);
        int encryptionContextSize = contextBytes.getInt();
        encryptionContext = new HashMap<>();
        for (int i = 0; i < encryptionContextSize; i++) {
            int keyLen = contextBytes.getInt();
            byte[] keyBytes = new byte[keyLen];
            contextBytes.get(keyBytes);

            int valueLen = contextBytes.getInt();
            byte[] valueBytes = new byte[valueLen];
            contextBytes.get(valueBytes);

            encryptionContext.put(new String(keyBytes, StandardCharsets.UTF_8), new String(valueBytes, StandardCharsets.UTF_8));
        }
    }
}
