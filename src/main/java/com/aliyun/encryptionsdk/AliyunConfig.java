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

import com.aliyun.encryptionsdk.kms.BackoffStrategy;
import com.aliyun.encryptionsdk.kms.FullJitterBackoffStrategy;
import com.aliyuncs.auth.*;
import com.aliyuncs.profile.DefaultProfile;

public class AliyunConfig {
    /**
     * 使用AliyunKmsClient默认重试次数
     */
    private static final int MAX_RETRIES = 5;

    private int maxRetries;
    private BackoffStrategy backoffStrategy;
    private AlibabaCloudCredentialsProvider provider;

    public AliyunConfig() {
        this.maxRetries = MAX_RETRIES;
        this.backoffStrategy = new FullJitterBackoffStrategy(200L, 10000L);
    }

    public AliyunConfig(AlibabaCloudCredentialsProvider provider) {
        this.maxRetries = MAX_RETRIES;
        this.backoffStrategy = new FullJitterBackoffStrategy(200L, 10000L);
        this.provider = provider;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    public BackoffStrategy getBackoffStrategy() {
        return backoffStrategy;
    }

    public void setBackoffStrategy(BackoffStrategy backoffStrategy) {
        this.backoffStrategy = backoffStrategy;
    }

    public AlibabaCloudCredentialsProvider getProvider() {
        return provider;
    }

    public void setProvider(AlibabaCloudCredentialsProvider provider) {
        this.provider = provider;
    }

    public void withAccessKey(String accessKeyId, String accessKeySecret) {
        this.provider = new StaticCredentialsProvider(new BasicCredentials(accessKeyId, accessKeySecret));
    }

    public void withToken(String stsAccessKeyId, String stsAccessKeySecret, String stsToken) {
        this.provider = new StaticCredentialsProvider(new BasicSessionCredentials(stsAccessKeyId, stsAccessKeySecret, stsToken));
    }

    public void withRamRoleArnOrSts(String accessKeyId, String accessKeySecret, String regionId, String roleArn) {
        this.provider = new STSAssumeRoleSessionCredentialsProvider(new BasicCredentials(accessKeyId, accessKeySecret), roleArn, DefaultProfile.getProfile(regionId));
    }

    public void withEcsRamRole(String roleName) {
        this.provider = new InstanceProfileCredentialsProvider(roleName);
    }
}
