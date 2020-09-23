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

package com.aliyun.encryptionsdk.examples.credentials;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;

import java.util.Collections;

import static org.junit.Assert.assertArrayEquals;

/**
 *
 * 通过ECSRamRole进行访问认证
 */
public class EcsRamRoleSample {
    private static final String PLAIN_TEXT = "this is test.";
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";

    public static void main(String[] args) {
        AliyunConfig config = new AliyunConfig();
        config.withEcsRamRole("EcsRamRoleTest");
        AliyunCrypto crypto = new AliyunCrypto(config);
        DefaultDataKeyProvider defaultDataKeyProvider = new DefaultDataKeyProvider(KEY_ID);
        try {
            CryptoResult<byte[]> encryptResult = crypto.encrypt(defaultDataKeyProvider, PLAIN_TEXT.getBytes(), Collections.singletonMap("sample", "Context"));
            CryptoResult<byte[]> decryptResult = crypto.decrypt(defaultDataKeyProvider, encryptResult.getResult());
            assertArrayEquals(decryptResult.getResult(), PLAIN_TEXT.getBytes());
        } catch (InvalidAlgorithmException | UnFoundDataKeyException e) {
            System.out.println("Failed.");
            System.out.println("Error message: " + e.getMessage());
        }
        System.out.println("============================");
        System.out.println("createAliyunConfigWithEcsRamRole finish");
        System.out.println("============================");
    }
}
