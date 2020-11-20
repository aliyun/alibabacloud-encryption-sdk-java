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

package com.aliyun.encryptionsdk;

import com.aliyun.encryptionsdk.ckm.CryptoKeyManager;
import com.aliyun.encryptionsdk.ckm.DefaultCryptoKeyManager;
import com.aliyun.encryptionsdk.handler.DefaultEncryptHandler;
import com.aliyun.encryptionsdk.handler.EncryptHandler;
import com.aliyun.encryptionsdk.kms.DefaultAliyunKms;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

/**
 * EncryptionSDK的主类，所有的加/解密操作都应该通过该类中的方法开始
 */
public class AliyunCrypto {
    /**
     * 加/解密处理类
     */
    private EncryptHandler encryptHandler;

    /**
     * aliyun访问配置类
     */
    private AliyunConfig config;

    private CryptoKeyManager cryptoKeyManager;

    public AliyunCrypto(AliyunConfig config) {
        this(config, LoggerFactory.getLogger(Constants.MODE_NAME));
    }

    public AliyunCrypto(AliyunConfig config, Logger logger) {
        this.config = config;
        this.encryptHandler = new DefaultEncryptHandler();
        this.cryptoKeyManager = new DefaultCryptoKeyManager();
        if (!CommonLogger.isRegistered(Constants.MODE_NAME)) {
            CommonLogger.registerLogger(Constants.MODE_NAME, logger);
        }
    }

    public void setEncryptHandler(EncryptHandler encryptHandler) {
        this.encryptHandler = encryptHandler;
    }

    public void setConfig(AliyunConfig config) {
        this.config = config;
    }

    public void setCryptoKeyManager(CryptoKeyManager cryptoKeyManager) {
        this.cryptoKeyManager = cryptoKeyManager;
    }

    /**
     * 使用 {@link BaseDataKeyProvider} 生成dataKey加密 {@code plaintext}
     * 加密细节由 {@link EncryptHandler} 处理
     * @param provider 数据密钥提供
     * @param plainText 明文
     * @param encryptionContext 加密上下文
     * @return 加密结果
     */
    public CryptoResult<byte[]> encrypt(BaseDataKeyProvider provider, byte[] plainText, Map<String, String> encryptionContext) {
        provider.setAliyunKms(new DefaultAliyunKms(config));
        EncryptionMaterial material = cryptoKeyManager.getEncryptDataKeyMaterial(provider, encryptionContext, plainText.length);
        CipherMaterial cipherMaterial = encryptHandler.encrypt(plainText, material);
        byte[] processBytes = provider.processCipherMaterial(cipherMaterial);
        return new CryptoResult<>(processBytes, cipherMaterial);
    }

    /**
     * 使用 {@link BaseDataKeyProvider} 生成dataKey加密 {@code plaintext}
     */
    public CryptoResult<byte[]> encrypt(BaseDataKeyProvider provider, byte[] plainText) {
        return encrypt(provider, plainText, Collections.emptyMap());
    }

    /**
     * 使用 {@link BaseDataKeyProvider} 获取加密使用的dataKey解密 {@code cipherText}
     * @param provider 数据密钥提供
     * @param cipherText 密文
     * @return 解密结果
     */
    public CryptoResult<byte[]> decrypt(BaseDataKeyProvider provider, byte[] cipherText) {
        provider.setAliyunKms(new DefaultAliyunKms(config));
        CipherMaterial cipherMaterial = provider.getCipherMaterial(cipherText);
        CipherHeader cipherHeader = cipherMaterial.getCipherHeader();
        provider.setAlgorithm(cipherHeader.getAlgorithm());
        DecryptionMaterial material = cryptoKeyManager.getDecryptDataKeyMaterial(provider,
                cipherHeader.getEncryptionContext(), cipherHeader.getEncryptedDataKeys());
        return new CryptoResult<>(encryptHandler.decrypt(cipherMaterial, material), cipherMaterial);
    }

    /**
     * 读取 {@link InputStream} 内的字节数据，使用 {@link BaseDataKeyProvider} 加密后写入 {@link OutputStream}
     * @param provider 数据密钥提供
     * @param inputStream 待加密明文流
     * @param outputStream 已加密密文流
     * @param encryptionContext 加密上下文
     * @return 加密结果
     */
    public CryptoResult<OutputStream> encrypt(BaseDataKeyProvider provider, InputStream inputStream, OutputStream outputStream, Map<String, String> encryptionContext) {
        provider.setAliyunKms(new DefaultAliyunKms(config));
        EncryptionMaterial material = cryptoKeyManager.getEncryptDataKeyMaterial(provider, encryptionContext, -1);
        CipherMaterial cipherMaterial = encryptHandler.encryptStream(inputStream, outputStream, provider, material);
        return new CryptoResult<>(outputStream, cipherMaterial);
    }

    /**
     * 读取 {@link InputStream} 内的字节数据，使用 {@link BaseDataKeyProvider} 加密后写入 {@link OutputStream}
     */
    public CryptoResult<OutputStream> encrypt(BaseDataKeyProvider provider, InputStream inputStream, OutputStream outputStream) {
        return encrypt(provider, inputStream, outputStream, Collections.emptyMap());
    }

    /**
     * 读取 {@link InputStream} 内的字节数据，使用 {@link BaseDataKeyProvider} 解密后写入 {@link OutputStream}
     * @param provider 数据密钥提供
     * @param inputStream 加密密文流
     * @param outputStream 明文数据流
     * @return 解密结果
     */
    public CryptoResult<OutputStream> decrypt(BaseDataKeyProvider provider, InputStream inputStream, OutputStream outputStream) {
        provider.setAliyunKms(new DefaultAliyunKms(config));
        CipherMaterial cipherMaterial = provider.getCipherMaterial(inputStream);
        CipherHeader cipherHeader = cipherMaterial.getCipherHeader();
        provider.setAlgorithm(cipherHeader.getAlgorithm());
        DecryptionMaterial material = cryptoKeyManager.getDecryptDataKeyMaterial(provider,
                cipherHeader.getEncryptionContext(), cipherHeader.getEncryptedDataKeys());
        encryptHandler.decryptStream(inputStream, outputStream, cipherMaterial, material);
        return new CryptoResult<>(outputStream, cipherMaterial);
    }

    /**
     * 使用 {@link SignatureProvider} 处理加签请求
     * @param provider 签名提供
     * @param content 签名内容
     * @param type 内容类型
     * @return 签名结果
     */
    public SignatureResult<byte[]> sign(SignatureProvider provider, byte[] content, ContentType type) {
        if (provider == null) {
            throw new NullPointerException("signature provider must not be null");
        }
        provider.setAliyunKms(new DefaultAliyunKms(config));
        SignatureMaterial signatureMaterial = cryptoKeyManager.getSignatureMaterial(provider, content, type);
        return new SignatureResult<>(Base64.getDecoder().decode(signatureMaterial.getValue()));
    }

    /**
     * 使用 {@link SignatureProvider} 处理验签请求
     * @param provider 签名提供
     * @param content 验签内容
     * @param signature 签名结果
     * @param type 内容类型
     * @return 验签结果
     */
    public Boolean verify(SignatureProvider provider, byte[] content, byte[] signature, ContentType type) {
        if (provider == null) {
            throw new NullPointerException("signature provider must not be null");
        }
        provider.setAliyunKms(new DefaultAliyunKms(config));
        VerifyMaterial verifyMaterial = cryptoKeyManager.getVerifyMaterial(provider, content, signature, type);
        return verifyMaterial.getValue();
    }
}
