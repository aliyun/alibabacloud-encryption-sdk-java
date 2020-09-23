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

/**
 * 用于密材料的缓存抽象，维护从缓存标识符到EncryptEntry与DecryptEntry的映射关系。
 * 缓存仅关注密钥材料以及有关缓存使用限制的数据统计，实际执行限制由外层调用方处理。
 */
public interface DataKeyCache {

    /**
     * 从缓存中搜索一个与标识符匹配的加密密钥条目
     * @param key 缓存标识符
     * @param usageInfo 本次获取密钥材料增加的使用量
     * @return 加密材料条目
     */
    EncryptEntry getEncryptEntry(String key, UsageInfo usageInfo);

    /**
     * 向缓存中添加一个新的加密密钥材料
     * @param key 缓存标识符
     * @param survivalTime 缓存最大生存时间
     * @param material 加密密钥材料
     * @param usageInfo 密钥初始使用情况
     */
    void putEncryptEntry(String key, long survivalTime, EncryptionMaterial material, UsageInfo usageInfo);

    /**
     * 从缓存中搜索一个与标识符匹配的解密密钥条目
     * @param key 缓存标识符
     * @return 解密材料条目
     */
    DecryptEntry getDecryptEntry(String key);

    /**
     * 向缓存中添加一个新的解密密钥材料
     * @param key 缓存标识符
     * @param survivalTime 缓存最大生存时间
     * @param material 解密密钥材料
     */
    void putDecryptEntry(String key, long survivalTime, DecryptionMaterial material);

    /**
     * 缓存的加密密钥条目抽象接口
     */
    interface EncryptEntry {
        String getCacheId();
        EncryptionMaterial getMaterial();
        UsageInfo getUsageInfo();
        void invalid();
    }

    /**
     * 缓存的解密密钥条目抽象接口
     */
    interface DecryptEntry {
        String getCacheId();
        DecryptionMaterial getMaterial();
        void invalid();
    }

    /**
     * 密钥材料的使用情况，保存了已加密字节数和加密信息条数
     */
    class UsageInfo {
        private long encryptedBytes;
        private long encryptedMessages;

        public UsageInfo(long encryptedBytes, long encryptedMessages) {
            this.encryptedBytes = encryptedBytes;
            this.encryptedMessages = encryptedMessages;
        }

        public long getEncryptedBytes() {
            return encryptedBytes;
        }

        public long getEncryptedMessages() {
            return encryptedMessages;
        }

        public UsageInfo add(UsageInfo usageInfo) {
            return new UsageInfo(safeAdd(encryptedBytes, usageInfo.encryptedBytes),
                    safeAdd(encryptedMessages, usageInfo.encryptedMessages));
        }

        private long safeAdd(long a, long b) {
            long r = a + b;
            if (a > 0 && b > 0 && r < a) {
                return Long.MAX_VALUE;
            }
            return r;
        }

        @Override
        public String toString() {
            return "encryptedBytes: " + encryptedBytes
                    + " encryptedMessages: " + encryptedMessages;
        }
    }
}
