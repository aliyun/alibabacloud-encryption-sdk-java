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

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class EncryptedDataKey implements Comparable<EncryptedDataKey> {
    private static final Charset DATAKEY_ENCODING = StandardCharsets.UTF_8;

    private byte[] keyId;
    private byte[] dataKey;

    public EncryptedDataKey(String keyId, String dataKey) {
        this.keyId = keyId.getBytes(DATAKEY_ENCODING);
        this.dataKey = dataKey.getBytes(DATAKEY_ENCODING);
    }

    public EncryptedDataKey(byte[] keyId, byte[] dataKey) {
        this.keyId = keyId;
        this.dataKey = dataKey;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public byte[] getDataKey() {
        return dataKey;
    }

    public String getKeyIdString() {
        return new String(keyId, DATAKEY_ENCODING);
    }

    public String getDataKeyString() {
        return new String(dataKey, DATAKEY_ENCODING);
    }

    public byte[] toByteArray() {
        int outLen = 2 * (Integer.BYTES) + keyId.length + dataKey.length;
        ByteBuffer out = ByteBuffer.allocate(outLen);
        out.putInt(keyId.length);
        out.put(keyId);
        out.putInt(dataKey.length);
        out.put(dataKey);
        return out.array();
    }

    @Override
    public int compareTo(EncryptedDataKey o) {
        int min = Math.min(keyId.length, o.keyId.length);
        for (int i = 0; i < min; i++ ) {
            int a = keyId[i] & 0xFF;
            int b = o.keyId[i] & 0xFF;
            if (a != b) {
                return a - b;
            }
        }
        return keyId.length - o.keyId.length;
    }
}
