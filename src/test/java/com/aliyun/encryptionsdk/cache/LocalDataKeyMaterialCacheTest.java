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
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.*;

import static org.junit.Assert.*;

public class LocalDataKeyMaterialCacheTest {
    private final static DataKeyCache.UsageInfo ZERO_USAGE_INFO = new DataKeyCache.UsageInfo(0, 0);

    LocalDataKeyMaterialCache cache;
    Long survivalTime = 1000L;

    private static final String ENTRY_KEY0 = UUID.randomUUID().toString();
    private static final String ENTRY_KEY1 = UUID.randomUUID().toString();
    private static final String ENTRY_KEY2 = UUID.randomUUID().toString();
    private static final String ENTRY_KEY3 = UUID.randomUUID().toString();
    private static final String ENTRY_KEY4 = UUID.randomUUID().toString();
    private static final String ENTRY_KEY5 = UUID.randomUUID().toString();
    private static final List<String> ENTRY_KEY_LIST = Arrays.asList(ENTRY_KEY0, ENTRY_KEY1, ENTRY_KEY2, ENTRY_KEY3, ENTRY_KEY4, ENTRY_KEY5);

    @Before
    public void setUp() {
        cache = new LocalDataKeyMaterialCache(5);
    }

    @Test
    public void whenNoEntriesInCache_noEntriesReturned() {
        assertNull(cache.getDecryptEntry(ENTRY_KEY0));
        assertNull(cache.getEncryptEntry(ENTRY_KEY0, ZERO_USAGE_INFO));
    }

    @Test
    public void whenEntriesAddedToDecryptCache_correctEntriesReturned() {
        DecryptionMaterial result0 = TestFixtures.createDecryptResult(0);
        DecryptionMaterial result1 = TestFixtures.createDecryptResult(1);

        cache.putDecryptEntry(ENTRY_KEY0, survivalTime, result0);
        cache.putDecryptEntry(ENTRY_KEY1, survivalTime, result1);
        assertEquals(result0, cache.getDecryptEntry(ENTRY_KEY0).getMaterial());
        assertEquals(result1, cache.getDecryptEntry(ENTRY_KEY1).getMaterial());
    }

    @Test
    public void whenManyDecryptEntriesAdded_LRURespected() {
        DecryptionMaterial[] results = new DecryptionMaterial[6];

        for (int i = 0; i < results.length; i++) {
            results[i] = TestFixtures.createDecryptResult(i);
        }

        cache.putDecryptEntry(ENTRY_KEY0, survivalTime, results[0]);
        cache.putDecryptEntry(ENTRY_KEY1, survivalTime, results[1]);
        cache.putDecryptEntry(ENTRY_KEY2, survivalTime, results[2]);
        cache.putDecryptEntry(ENTRY_KEY3, survivalTime, results[3]);
        cache.putDecryptEntry(ENTRY_KEY4, survivalTime, results[4]);

        // make entry 0 and entry 1 most recently used
        assertEquals(results[0], cache.getDecryptEntry(ENTRY_KEY0).getMaterial());
        assertEquals(results[1], cache.getDecryptEntry(ENTRY_KEY1).getMaterial());

        // entry 1 is evicted
        cache.putDecryptEntry(ENTRY_KEY5, survivalTime, results[5]);

        for (int i = 0; i < results.length; i++) {
            DecryptionMaterial actualResult =
                    Optional.ofNullable(cache.getDecryptEntry(ENTRY_KEY_LIST.get(i)))
                            .map(DataKeyCache.DecryptEntry::getMaterial)
                            .orElse(null);
            DecryptionMaterial expected = (i == 2) ? null : results[i];

            assertEquals("index " + i, expected, actualResult);
        }
    }

    @Test
    public void whenEncryptEntriesAdded_theyCanBeRetrieved() {
        EncryptionMaterial
                result1a = TestFixtures.createMaterialsResult(0);
        EncryptionMaterial
                result1b = TestFixtures.createMaterialsResult(0);
        EncryptionMaterial
                result2 = TestFixtures.createMaterialsResult(1);

        cache.putEncryptEntry(ENTRY_KEY0, survivalTime, result1a, ZERO_USAGE_INFO);
        cache.putEncryptEntry(ENTRY_KEY0, survivalTime, result1b, ZERO_USAGE_INFO);
        cache.putEncryptEntry(ENTRY_KEY1, survivalTime, result2, ZERO_USAGE_INFO);

        assertEncryptEntry(ENTRY_KEY0, result1b);
        assertEncryptEntry(ENTRY_KEY1, result2);
    }

    @Test
    public void whenManyEncryptEntriesAdded_LRUIsRespected() {
        EncryptionMaterial[] results = new EncryptionMaterial[6];
        for (int i = 0; i < results.length; i++) {
            results[i] = TestFixtures.createMaterialsResult(i / 3);
            cache.putEncryptEntry(ENTRY_KEY_LIST.get(i), survivalTime, results[i], ZERO_USAGE_INFO);
        }

        for (int i = 0; i < results.length; i++) {
            EncryptionMaterial expected = i == 0 ? null : results[i];

            assertEncryptEntry(ENTRY_KEY_LIST.get(i), expected);
        }
    }

    @Test
    public void whenManyEncryptEntriesAdded_andEntriesTouched_LRUIsRespected() {
        EncryptionMaterial[] results = new EncryptionMaterial[6];
        for (int i = 0; i < 3; i++) {
            results[i] = TestFixtures.createMaterialsResult(0);
            cache.putEncryptEntry(ENTRY_KEY_LIST.get(i), survivalTime, results[i], ZERO_USAGE_INFO);
        }
        cache.getEncryptEntry(ENTRY_KEY0, ZERO_USAGE_INFO);

        for (int i = 3; i < 6; i++) {
            results[i] = TestFixtures.createMaterialsResult(0);
            cache.putEncryptEntry(ENTRY_KEY_LIST.get(i), survivalTime, results[i], ZERO_USAGE_INFO);
        }

        for (int i = 0; i < results.length; i++) {
            EncryptionMaterial expected = i == 1 ? null : results[i];

            assertEncryptEntry(ENTRY_KEY_LIST.get(i), expected);
        }
    }

    @Test
    public void whenManyEncryptEntriesAdded_andEntryInvalidated_LRUIsRespected() {
        EncryptionMaterial[] results = new EncryptionMaterial[6];
        for (int i = 0; i < 3; i++) {
            results[i] = TestFixtures.createMaterialsResult(0);
            cache.putEncryptEntry(ENTRY_KEY_LIST.get(i), survivalTime, results[i], ZERO_USAGE_INFO);
        }

        cache.getEncryptEntry(ENTRY_KEY2, ZERO_USAGE_INFO).invalid();

        for (int i = 3; i < 6; i++) {
            results[i] = TestFixtures.createMaterialsResult(0);
            cache.putEncryptEntry(ENTRY_KEY_LIST.get(i), survivalTime, results[i], ZERO_USAGE_INFO);
        }

        for (int i = 0; i < results.length; i++) {
            EncryptionMaterial expected = i == 2 ? null : results[i];

            assertEncryptEntry(ENTRY_KEY_LIST.get(i), expected);
        }
    }

    @Test
    public void whenTTLExceeded_encryptEntriesAreEvicted() throws Exception {
        EncryptionMaterial result = createResult();
        cache.putEncryptEntry(ENTRY_KEY0, 500, result, ZERO_USAGE_INFO);
        Thread.sleep(450);

        assertEncryptEntry(ENTRY_KEY0, result);
        Thread.sleep(51);
        assertEncryptEntry(ENTRY_KEY0, null);

        // Verify that the cache isn't hanging on to memory once it notices the entry is expired
        assertEquals(0, getCacheMap(cache).size());
    }

    @Test
    public void whenManyEntriesExpireAtOnce_expiredEncryptEntriesStillNotReturned() throws InterruptedException {
        cache = new LocalDataKeyMaterialCache(200);

        for (int i = 0; i < 100; i++) {
            cache.putEncryptEntry(UUID.randomUUID().toString(), 500, createResult(), ZERO_USAGE_INFO);
        }

        cache.putEncryptEntry(ENTRY_KEY0, 501, createResult(), ZERO_USAGE_INFO);
        Thread.sleep(502);

        assertEncryptEntry(ENTRY_KEY0, null);
    }

    @Test
    public void whenAccessed_encryptEntryTTLNotReset() throws InterruptedException {
        EncryptionMaterial result = createResult();
        cache.putEncryptEntry(ENTRY_KEY0, survivalTime, result, ZERO_USAGE_INFO);

        Thread.sleep(999);
        assertEncryptEntry(ENTRY_KEY0, result);
        Thread.sleep(1);
        assertEncryptEntry(ENTRY_KEY0, null);
    }

    @Test
    public void whenTTLExceeded_decryptEntriesAreEvicted() throws Exception {
        DecryptionMaterial result = TestFixtures.createDecryptResult(0);

        cache.putDecryptEntry(ENTRY_KEY0, survivalTime, result);

        Thread.sleep(survivalTime + 1);
        assertNull(cache.getDecryptEntry(ENTRY_KEY0));

        // Verify that the cache isn't hanging on to memory once it notices the entry is expired
        assertEquals(0, getCacheMap(cache).size());
    }

    @Test
    public void whenAccessed_decryptEntryTTLNotReset() throws InterruptedException {
        DecryptionMaterial result = TestFixtures.createDecryptResult(0);

        cache.putDecryptEntry(ENTRY_KEY0, survivalTime, result);

        Thread.sleep(500);
        assertNotNull(cache.getDecryptEntry(ENTRY_KEY0));
        Thread.sleep(501);
        assertNull(cache.getDecryptEntry(ENTRY_KEY0));
    }

    @Test
    public void whenManyEntriesExpireAtOnce_expiredDecryptEntriesStillNotReturned() throws InterruptedException {
        cache = new LocalDataKeyMaterialCache(200);

        for (int i = 0; i < 100; i++) {
            cache.putEncryptEntry(UUID.randomUUID().toString(), 500, createResult(), ZERO_USAGE_INFO);
        }

        DecryptionMaterial result = TestFixtures.createDecryptResult(0);
        cache.putDecryptEntry(ENTRY_KEY0, 501, result);

        // our encrypt entries will expire first
        Thread.sleep(502);
        assertNull(cache.getDecryptEntry(ENTRY_KEY0));
    }

    @Test
    public void testDecryptInvalid() {
        DecryptionMaterial result = TestFixtures.createDecryptResult(0);

        cache.putDecryptEntry(ENTRY_KEY0, survivalTime, result);

        cache.getDecryptEntry(ENTRY_KEY0).invalid();
        assertNull(cache.getDecryptEntry(ENTRY_KEY0));
    }


    private void assertEncryptEntry(String cacheKey, EncryptionMaterial expectedResult) {
        DataKeyCache.EncryptEntry entry = cache.getEncryptEntry(cacheKey, ZERO_USAGE_INFO);
        EncryptionMaterial actual = entry == null ? null : entry.getMaterial();
        assertEquals(expectedResult, actual);
    }

    private EncryptionMaterial createResult() {
        return TestFixtures.createMaterialsResult(0);
    }

    private Map getCacheMap(LocalDataKeyMaterialCache cache) throws Exception {
        Field field = LocalDataKeyMaterialCache.class.getDeclaredField("cacheMap");
        field.setAccessible(true);

        return (Map) field.get(cache);
    }
}
