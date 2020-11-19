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

import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.SecurityProcessException;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.Constants;
import com.aliyun.encryptionsdk.model.CryptoAlgorithm;
import com.aliyun.encryptionsdk.model.CipherHeader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * 处理加/解密流程并返回结果
 */
public class AlgorithmHandler {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private int mode;
    private Cipher cipher;
    private CryptoAlgorithm algorithm;
    private SecretKey keySpec;

    public AlgorithmHandler(CryptoAlgorithm algorithm, SecretKey keySpec, int mode) {
        try {
            this.cipher = Cipher.getInstance(algorithm.getCryptoName(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Invalid algorithm: " + algorithm.getCryptoName(), e);
            throw new InvalidAlgorithmException("Invalid algorithm: " + algorithm.getCryptoName(), e);
        }
        this.algorithm = algorithm;
        this.keySpec = keySpec;
        this.mode = mode;
    }

    /**
     * 使用 {@link Cipher} 处理数据
     * @param iv 随机向量
     * @param contentAad 身份验证数据
     * @param content 需要处理的数据
     * @param off 需要处理数据的偏移量
     * @param len 需要处理数据的长度
     * @return 处理完成后的数据
     */
    public byte[] cipherData(byte[] iv, byte[] contentAad, final byte[] content, int off, int len) {
        if (iv.length != algorithm.getIvLen()) {
            throw new IllegalArgumentException("Invalid iv length: " + iv.length);
        }
        AlgorithmParameterSpec spec = algorithm.getSpec(iv);
        try {
            cipher.init(mode, keySpec, spec);
            if (contentAad != null && algorithm.isWithAad()) {
                cipher.updateAAD(contentAad);
            }
            return cipher.doFinal(content, off, len);
        } catch (Exception e) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Failed to obtain " + algorithm.getCryptoName() + " cipher result" ,e);
            throw new SecurityProcessException("Failed to obtain " + algorithm.getCryptoName() + " cipher result", e);
        }
    }

    public byte[] headerGcmEncrypt(byte[] iv, byte[] contentAad, final byte[] content, int off, int len) {
        try {
            Cipher gcmCipher;
            if(algorithm.getKeyName().equals("SM4"))
                gcmCipher = Cipher.getInstance("SM4/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            else
                gcmCipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            if (iv.length != CipherHeader.HEADER_IV_LEN) {
                throw new IllegalArgumentException("Invalid iv length: " + iv.length);
            }
            AlgorithmParameterSpec spec = new GCMParameterSpec(algorithm.getBlockSize() * 8, iv);

            gcmCipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
            if (contentAad != null) {
                gcmCipher.updateAAD(contentAad);
            }
            return gcmCipher.doFinal(content, off, len);
        } catch (Exception e) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Failed to obtain " + algorithm.getCryptoName() + " cipher result" ,e);
            throw new SecurityProcessException("Failed to obtain " + algorithm.getCryptoName() + " cipher result", e);
        }
    }

}
