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

import com.aliyun.encryptionsdk.cache.DataKeyCache;
import com.aliyun.encryptionsdk.cache.LocalDataKeyMaterialCache;
import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.exception.InvalidArgumentException;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * CachingCryptoKeyManager包装了另一个 {@link CryptoKeyManager}，并缓存了密钥材料结果。
 * 减少从kms获取密钥材料的调用次数，有助于提高性能或降低成本。
 * <p>
 * 重复使用相同的密钥材料加密数据可能会导致密钥泄露后大量数据的泄密，所以对于每一个密钥
 * 材料都做了最大字节数或者最大加密信息数的限制，超过限制将重新获取新密钥材料，同时每个
 * 密钥也设置了最大生成时间。（注：当 {@code maxEncryptionBytes} 与 {@code maxEncryptionMessages}
 * 不设置或者设置为Long.MAX_VALUE时，该密钥材料不受最大字节数或者最大加密信息数限制）
 * <p>
 * {@link DataKeyCache} 是缓存密钥材料的接口， {@link LocalDataKeyMaterialCache} 为缓存
 * 默认实现。用户可以自定义实现该接口调整缓存的存储方案，比如redis等。
 * <p>
 * 一次请求是否会命中缓存由以下几点共同决定：
 * {@link CryptoAlgorithm} 算法信息
 * {@code encryptionContext} 加密上下文
 * {@link EncryptedDataKey} 加密的dataKey（仅解密时需要）
 * 以上几点通过SHA散列算法形成信息摘要作为key存储需要缓存的密钥材料实例
 */
public class CachingCryptoKeyManager implements CryptoKeyManager {
    private static final long MAX_TIME = 1000 * 60;
    private static final long MAX_BYTE = Long.MAX_VALUE;
    private static final long MAX_MESSAGE = Long.MAX_VALUE;

    private DataKeyCache cache;

    private long maxSurvivalTime;
    private long maxEncryptionBytes;
    private long maxEncryptionMessages;

    public CachingCryptoKeyManager(DataKeyCache cache) {
        this.cache = cache;
        this.maxSurvivalTime = MAX_TIME;
        this.maxEncryptionBytes = MAX_BYTE;
        this.maxEncryptionMessages = MAX_MESSAGE;
    }

    public long getMaxSurvivalTime() {
        return maxSurvivalTime;
    }

    public void setMaxSurvivalTime(long maxSurvivalTime) {
        if (maxSurvivalTime < 0) {
            throw new InvalidArgumentException("maxSurvivalTime must be set to positive");
        }
        this.maxSurvivalTime = maxSurvivalTime;
    }

    public long getMaxEncryptionBytes() {
        return maxEncryptionBytes;
    }

    public void setMaxEncryptionBytes(long maxEncryptionBytes) {
        if (maxEncryptionBytes < 0) {
            throw new InvalidArgumentException("maxEncryptionBytes must be set to positive");
        }
        this.maxEncryptionBytes = maxEncryptionBytes;
    }

    public long getMaxEncryptionMessages() {
        return maxEncryptionMessages;
    }

    public void setMaxEncryptionMessages(long maxEncryptionMessages) {
        if (maxEncryptionMessages < 0) {
            throw new InvalidArgumentException("maxEncryptionMessages must be set to positive");
        }
        this.maxEncryptionMessages = maxEncryptionMessages;
    }

    @Override
    public EncryptionMaterial getEncryptDataKeyMaterial(BaseDataKeyProvider provider, Map<String, String> encryptionContext, long plaintextSize) {
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof("This encryption will enable caching");
        EncryptionMaterial material = new EncryptionMaterial();
        material.setEncryptionContext(encryptionContext);
        material.setAlgorithm(provider.getAlgorithm());

        if (plaintextSize == -1 || plaintextSize > maxEncryptionBytes) {
            return provider.encryptDataKey(material);
        }

        String cacheId = getCacheId(provider.getAlgorithm(), encryptionContext);
        DataKeyCache.UsageInfo usageInfo = new DataKeyCache.UsageInfo(plaintextSize, 1);
        DataKeyCache.EncryptEntry entry = cache.getEncryptEntry(cacheId, usageInfo);
        if (entry != null) {
            if (!isExceedMaxLimit(entry.getUsageInfo())) {
                DataKeyCache.UsageInfo nowUse = entry.getUsageInfo();
                CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("This encryption hits the cache to obtain the encryptionMaterial" +
                                "[CacheId: %s, EncryptionBytes: Total(%d) Used(%d->%d), EncryptionMessages: Total(%d) Used(%d->%d)]",
                        entry.getCacheId(), maxEncryptionBytes, nowUse.getEncryptedBytes() - plaintextSize, nowUse.getEncryptedBytes(),
                        maxEncryptionMessages, nowUse.getEncryptedMessages() - 1, nowUse.getEncryptedMessages()));
                return entry.getMaterial();
            }
            entry.invalid();
        }

        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof("This encryption misses the cache");
        EncryptionMaterial result = provider.encryptDataKey(material);
        cache.putEncryptEntry(cacheId, maxSurvivalTime, result, usageInfo);
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("Cache a encryptionMaterial[CacheId: %s]", cacheId));
        return result;
    }

    private boolean isExceedMaxLimit(DataKeyCache.UsageInfo usageInfo) {
        return usageInfo.getEncryptedBytes() > maxEncryptionBytes
                || usageInfo.getEncryptedMessages() > maxEncryptionMessages;
    }

    private String getCacheId(CryptoAlgorithm algorithm, Map<String, String> encryptionContext) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA");
            digestAlgorithm(digest, algorithm);
            digestContext(digest, encryptionContext);
            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new AliyunException("SHA MessageDigest not available", e);
        }
    }

    @Override
    public DecryptionMaterial getDecryptDataKeyMaterial(BaseDataKeyProvider provider, Map<String, String> encryptionContext, List<EncryptedDataKey> encryptedDataKeys) {
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof("This decryption will enable caching");
        DecryptionMaterial material = new DecryptionMaterial();
        material.setEncryptionContext(encryptionContext);
        material.setAlgorithm(provider.getAlgorithm());

        String cacheId = getCacheId(provider.getAlgorithm(), encryptionContext, encryptedDataKeys);
        DataKeyCache.DecryptEntry entry = cache.getDecryptEntry(cacheId);
        if (entry != null) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("This decryption hits the cache to obtain the decryptionMaterial[CacheId: %s]", entry.getCacheId()));
            return entry.getMaterial();
        }

        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof("This decryption misses the cache");
        DecryptionMaterial result = provider.decryptDataKey(material, encryptedDataKeys);
        cache.putDecryptEntry(cacheId, maxSurvivalTime, result);
        CommonLogger.getCommonLogger(Constants.MODE_NAME).infof(String.format("Cache a decryptionMaterial[CacheId: %s]", cacheId));
        return result;
    }

    private String getCacheId(CryptoAlgorithm algorithm, Map<String, String> encryptionContext, List<EncryptedDataKey> encryptedDataKeys) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA");
            digestAlgorithm(digest, algorithm);
            digestContext(digest, encryptionContext);
            digestEncryptedDataKeys(digest, encryptedDataKeys);
            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (Exception e) {
            throw new AliyunException("SHA MessageDigest not available", e);
        }
    }

    private void digestAlgorithm(MessageDigest digest, CryptoAlgorithm algorithm) {
        if (algorithm == null) {
            digest.update((byte) 0);
        } else {
            digest.update((byte) 1);
            algorithm.digestAlgorithm(digest);
        }
    }

    private void digestContext(MessageDigest digest, Map<String, String> encryptionContext) {
        if (encryptionContext == null) {
            digest.update((byte) 0);
        } else {
            digest.update((byte) 1);
            digest.update((byte) encryptionContext.size());
            TreeMap<String, String> map = new TreeMap<>(encryptionContext);
            map.forEach((key, value) -> {
                digest.update(key.getBytes(ENCODING));
                digest.update(value.getBytes(ENCODING));
            });
        }
    }

    private void digestEncryptedDataKeys(MessageDigest digest, List<EncryptedDataKey> encryptedDataKeys) {
        if (encryptedDataKeys == null) {
            digest.update((byte) 0);
        } else {
            digest.update((byte) 1);
            digest.update((byte) encryptedDataKeys.size());
            TreeSet<EncryptedDataKey> set = new TreeSet<>(encryptedDataKeys);
            set.forEach(key -> {
                digest.update(key.getKeyId());
                digest.update(key.getDataKey());
            });
        }
    }

    @Override
    public SignatureMaterial getSignatureMaterial(SignatureProvider provider, byte[] content, ContentType type) {
        SignatureMaterial material = new SignatureMaterial();
        material.setSignatureAlgorithm(provider.getSignatureAlgorithm());
        if (type.equals(ContentType.DIGEST)) {
            material.setDigest(content);
        } else {
            material.setMessage(content);
        }
        return provider.sign(material);
    }

    @Override
    public VerifyMaterial getVerifyMaterial(SignatureProvider provider, byte[] content, byte[] signature, ContentType type) {
        VerifyMaterial material = new VerifyMaterial();
        material.setSignature(signature);
        material.setSignatureAlgorithm(provider.getSignatureAlgorithm());
        if (type.equals(ContentType.DIGEST)) {
            material.setDigest(content);
        } else {
            material.setMessage(content);
        }
        return provider.verify(material);
    }
}
