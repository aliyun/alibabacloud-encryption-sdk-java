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

package com.aliyun.encryptionsdk.kms;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.TestAccount;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.HttpResponse;
import com.aliyuncs.kms.model.v20160120.GetSecretValueRequest;
import org.junit.Test;


import static org.junit.Assert.*;

public class AliyunKmsClientFactoryTest {
    private static final AliyunConfig CONFIG = TestAccount.AliyunKMS.getAliyunConfig();
    @Test
    public void testGetClient(){
        IAcsClient client = AliyunKmsClientFactory.getClient(CONFIG, "cn-hangzhou");
        assertNotNull(client);
        assertTrue(client instanceof DefaultAcsClient);
    }

    @Test
    public void testClientUseful() throws ClientException {
        IAcsClient client = AliyunKmsClientFactory.getClient(CONFIG, "cn-hangzhou");
        GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretName("testSecretName");
        HttpResponse httpResponse = client.doAction(request);
        assertEquals(200, httpResponse.getStatus());
    }
}
