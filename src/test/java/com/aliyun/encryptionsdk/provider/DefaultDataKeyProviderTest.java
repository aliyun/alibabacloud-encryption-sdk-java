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

package com.aliyun.encryptionsdk.provider;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import com.aliyun.encryptionsdk.TestAccount;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.Assert.assertArrayEquals;

public class DefaultDataKeyProviderTest {
    private static final String KEY_ID = "acs:kms:cn-hangzhou:1540355698848459:key/8f4e7312-b204-4f6b-b473-447fe038f1b9";
    private static final String PLAIN_TEXT = "this is test.";
    private static final AliyunConfig CONFIG = TestAccount.AliyunKMS.getAliyunConfig();
    @Test
    public void testBuildAndUseful() {
        AliyunCrypto sdk = new AliyunCrypto(CONFIG);

        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(KEY_ID);

        final byte[] cipherText = sdk.encrypt(dataKeyProvider, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), Collections.emptyMap()).getResult();
        final byte[] decryptResult = sdk.decrypt(dataKeyProvider, cipherText).getResult();

        assertArrayEquals(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), decryptResult);

    }
}
