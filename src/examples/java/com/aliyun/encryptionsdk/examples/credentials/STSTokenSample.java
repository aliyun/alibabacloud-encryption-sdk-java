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

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.UnFoundDataKeyException;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.auth.sts.AssumeRoleRequest;
import com.aliyuncs.auth.sts.AssumeRoleResponse;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import java.util.Collections;

import static org.junit.Assert.assertArrayEquals;

/**
 *
 * 使用STSToken进行访问认证（需自己维护token）
 */
public class STSTokenSample {
    private static final String PLAIN_TEXT = "this is test.";
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final String ACCESS_KEY_ID = System.getenv("<AccessKeyId>");
    private static final String ACCESS_KEY_SECRET = System.getenv("<AccessKeySecret>");
    private static final String REGION_ID = "cn-hangzhou";

    public static void main(String[] args) throws ClientException {
        String roleSessionName = "testRoleSession";
        String roleArn = "acs:ram::accountId:role/RoleName";
        AssumeRoleResponse assumeRoleResponse = getAssumeRole(roleArn, roleSessionName);
        AssumeRoleResponse.Credentials credentials = assumeRoleResponse.getCredentials();
        AliyunConfig config = new AliyunConfig();
        config.withToken(credentials.getAccessKeyId(), credentials.getAccessKeySecret(), credentials.getSecurityToken());
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
        System.out.println("createAliyunConfigWithToken finish");
        System.out.println("============================");
    }

    /**
     * 手动获取stsToken
     * @param roleArn
     * @param roleSessionName
     * @return
     * @throws ClientException
     */
    private static AssumeRoleResponse getAssumeRole(String roleArn, String roleSessionName) throws ClientException {
        AssumeRoleRequest request = new AssumeRoleRequest();
        request.setRoleArn(roleArn);
        request.setRoleSessionName(roleSessionName);
        IClientProfile profile = DefaultProfile.getProfile(REGION_ID, ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        DefaultAcsClient defaultAcsClient = new DefaultAcsClient(profile);
        return defaultAcsClient.getAcsResponse(request);
    }

}
