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

package com.aliyun.encryptionsdk.cache;

import com.aliyun.encryptionsdk.model.DecryptionMaterial;
import com.aliyun.encryptionsdk.model.EncryptionMaterial;

import java.util.LinkedHashMap;
import java.util.TreeSet;

/**
 * {@link DataKeyCache} 的默认实现，利用Java自带的 {@link LinkedHashMap} 实现的LRU
 * 本地缓存
 */
public class LocalDataKeyMaterialCache implements DataKeyCache {

    private static final int DEFAULT_CAPACITY = 10;

    /**
     * accessOrder设置为true将启用LRU效果
     */
    private LinkedHashMap<String, BaseEntry> cacheMap = new LinkedHashMap<>(16,0.75f,true);

    /**
     * 利用TreeSet的特殊结构，快速找到已经过期的条目
     */
    private TreeSet<BaseEntry> sortMap = new TreeSet<>();

    private final int capacity;

    public LocalDataKeyMaterialCache() {
        this.capacity = DEFAULT_CAPACITY;
    }

    public LocalDataKeyMaterialCache(int capacity) {
        this.capacity = capacity;
    }

    /**
     * 缓存条目的公共属性并且实现比较接口
     */
    private class BaseEntry implements Comparable<BaseEntry> {
        private String key;
        private long expireTime;
        private long createTime = System.currentTimeMillis();

        private BaseEntry(String key, long expireTime) {
            this.key = key;
            this.expireTime = expireTime;
        }

        public String getKey() {
            return key;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expireTime;
        }

        void expired() {
            removeEntry(this);
        }

        @Override
        public int compareTo(BaseEntry o) {
            int num =  Long.compare(this.expireTime, o.expireTime);
            return num == 0 ? Long.compare(this.createTime, o.createTime) : num;
        }
    }

    private class EncryptionEntry extends BaseEntry {
        private EncryptionMaterial material;
        private UsageInfo usageInfo;

        private EncryptionEntry(String key, long expireTime, EncryptionMaterial material, UsageInfo usageInfo) {
            super(key, expireTime);
            this.material = material;
            this.usageInfo = usageInfo;
        }

        /**
         * 使用锁保证在增加加密字节数和信息数时的原子性
         * @param usageInfo 增加的加密字节数和信息数
         * @return 增加后的密钥使用情况
         */
        synchronized UsageInfo addUsageInfo(UsageInfo usageInfo) {
            this.usageInfo = this.usageInfo.add(usageInfo);
            return this.usageInfo;
        }
    }

    /**
     * 返回给调用者的加密密钥条目
     * 在多线程的情况下，两个线程先后增加了密钥使用信息，后一个线程增加的使用量
     * 达到密钥使用限制会导致前一个线程也无法使用密钥材料，所以将内部缓存的密钥条
     * 目与外部使用条目分开处理
     */
    private class EncryptionEntryExposed implements EncryptEntry {
        private EncryptionEntry entry;
        private UsageInfo usageInfo;

        private EncryptionEntryExposed(EncryptionEntry entry, UsageInfo usageInfo) {
            this.entry = entry;
            this.usageInfo = usageInfo;
        }

        @Override
        public String getCacheId() {
            return entry.getKey();
        }

        @Override
        public EncryptionMaterial getMaterial() {
            return entry.material;
        }

        @Override
        public UsageInfo getUsageInfo() {
            return usageInfo;
        }

        @Override
        public void invalid() {
            removeEntry(entry);
        }
    }

    private class DecryptionEntry extends BaseEntry implements DecryptEntry {
        private DecryptionMaterial material;

        public DecryptionEntry(String key, long expireTime, DecryptionMaterial material) {
            super(key, expireTime);
            this.material = material;
        }

        @Override
        public String getCacheId() {
            return getKey();
        }

        @Override
        public DecryptionMaterial getMaterial() {
            return material;
        }

        @Override
        public void invalid() {
            removeEntry(this);
        }
    }

    /**
     * 从缓存中删除该条目
     * @param entry 需要删除的缓存条目
     */
    private synchronized void removeEntry(BaseEntry entry) {
        cacheMap.remove(entry.key, entry);
        sortMap.remove(entry);
    }

    @Override
    public EncryptEntry getEncryptEntry(String key, UsageInfo usageInfo) {
        EncryptionEntry entry = (EncryptionEntry)getEntry(key);
        if (entry == null) {
            return null;
        }
        UsageInfo info = entry.addUsageInfo(usageInfo);
        return new EncryptionEntryExposed(entry, info);
    }

    @Override
    public void putEncryptEntry(String key, long survivalTime, EncryptionMaterial material, UsageInfo usageInfo) {
        EncryptionEntry encryptEntry = new EncryptionEntry(key, System.currentTimeMillis() + survivalTime, material, usageInfo);
        putEntry(encryptEntry);
    }

    @Override
    public DecryptEntry getDecryptEntry(String key) {
        return (DecryptEntry)getEntry(key);
    }

    @Override
    public void putDecryptEntry(String key, long survivalTime, DecryptionMaterial material) {
        DecryptionEntry entry = new DecryptionEntry(key, System.currentTimeMillis() + survivalTime, material);
        putEntry(entry);
    }

    private synchronized BaseEntry getEntry(String key) {
        BaseEntry entry = cacheMap.get(key);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired()) {
            entry.expired();
            return null;
        }
        return entry;
    }

    private synchronized void putEntry(BaseEntry entry) {
        BaseEntry oldEntry = cacheMap.put(entry.key, entry);
        if (oldEntry != null ){
            removeEntry(oldEntry);
        }
        sortMap.add(entry);
        checkCapacity();
    }

    /**
     * 检查容量，超出容量时按照LRU规则淘汰条目
     */
    private synchronized void checkCapacity() {
        eliminate();
        while (cacheMap.size() > capacity) {
            removeEntry(cacheMap.values().iterator().next());
        }
    }

    /**
     * 淘汰过期的缓存条目
     */
    private void eliminate() {
        while (!sortMap.isEmpty() && sortMap.first().expireTime < System.currentTimeMillis()) {
            removeEntry(sortMap.first());
        }
    }


}
