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

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;

public enum CryptoAlgorithm {
    /**
     * AES/GCM/NoPadding 128
     */
    AES_GCM_NOPADDING_128("AES", "AES_128", "AES/GCM/NoPadding", 16, 12, 16, 16, 1, true),
    /**
     * AES/GCM/NoPadding 256
     */
    AES_GCM_NOPADDING_256("AES", "AES_256", "AES/GCM/NoPadding", 32, 12, 16, 16, 2, true),

    /**
     * AES/CBC/NoPadding 128
     */
    AES_CBC_NOPADDING_128("AES", "AES_128", "AES/CBC/NoPadding", 16, 16, 0, 16, 3, false),
    /**
     * AES/CBC/NoPadding 256
     */
    AES_CBC_NOPADDING_256("AES", "AES_256", "AES/CBC/NoPadding", 32, 16, 0, 16, 4, false),
    /**
     * AES/CBC/PKCS5Padding 128
     */
    AES_CBC_PKCS5_128("AES", "AES_128", "AES/CBC/PKCS5Padding", 16, 16, 0, 16, 5, false),
    /**
     * AES/CBC/PKCS5Padding 256
     */
    AES_CBC_PKCS5_256("AES", "AES_256", "AES/CBC/PKCS5Padding", 32, 16, 0, 16, 6, false),

    /**
     * AES/CTR/NoPadding 128
     */
    AES_CTR_NOPADDING_128("AES", "AES_128", "AES/CTR/NoPadding", 16, 16, 0, 16, 7, false),
    /**
     * AES/CTR/NoPadding 256
     */
    AES_CTR_NOPADDING_256("AES", "AES_256", "AES/CTR/NoPadding", 32, 16, 0, 16, 8, false),

    /**
     * SM4/GCM/NoPadding 128
     */
    SM4_GCM_NOPADDING_128("SM4", "SM4_128", "SM4/GCM/NoPadding", 16, 12, 16, 16, 9, true),

    /**
     * SM4/CBC/NoPadding 128
     */
    SM4_CBC_NOPADDING_128("SM4", "SM4_128", "SM4/CBC/NoPadding", 16, 16, 0, 16, 10, false),
    /**
     * SM4/CBC/PKCS5Padding 128
     */
    SM4_CBC_PKCS5_128("SM4", "SM4_128", "SM4/CBC/PKCS5Padding", 16, 16, 0, 16, 11, false),

    /**
     * SM4/CTR/NoPadding 128
     */
    SM4_CTR_NOPADDING_128("SM4", "SM4_128", "SM4/CTR/NoPadding", 16, 16, 0, 16, 12, false),
    ;

    private String keyName;
    private String keySpec;
    private String cryptoName;
    private int keyLen;
    private int ivLen;
    private int tagLen;
    private int blockSize;
    private int value;
    private boolean withAad;

    CryptoAlgorithm(String keyName, String keySpec, String cryptoName, int keyLen, int ivLen, int tagLen, int blockSize, int value, boolean withAad) {
        this.keyName = keyName;
        this.keySpec = keySpec;
        this.cryptoName = cryptoName;
        this.keyLen = keyLen;
        this.ivLen = ivLen;
        this.tagLen = tagLen;
        this.blockSize = blockSize;
        this.value = value;
        this.withAad = withAad;
    }

    public String getKeyName() {
        return keyName;
    }

    public String getKeySpec() {
        return keySpec;
    }

    public String getCryptoName() {
        return cryptoName;
    }

    public int getKeyLen() {
        return keyLen;
    }

    public int getIvLen() {
        return ivLen;
    }

    public int getTagLen() {
        return tagLen;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public int getValue() {
        return value;
    }

    public boolean isWithAad() {
        return withAad;
    }

    public AlgorithmParameterSpec getSpec(byte[] iv) {
        switch (this) {
            case AES_GCM_NOPADDING_128:
            case AES_GCM_NOPADDING_256:
                return new GCMParameterSpec(this.getTagLen() * 8, iv);
            default:
                return new IvParameterSpec(iv);
        }
    }

    public void digestAlgorithm(MessageDigest digest) {
        digest.update((byte) value);
    }

    public static CryptoAlgorithm getAlgorithm(int value) {
        for (CryptoAlgorithm algorithm: CryptoAlgorithm.values()) {
            if (algorithm.getValue() == value) {
                return algorithm;
            }
        }
        return null;
    }
}
