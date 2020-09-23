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

import com.aliyuncs.exceptions.ClientException;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BackoffUtilsTest {
    private final static String REJECTED_THROTTLING = "Rejected.Throttling";
    private final static String SERVICE_UNAVAILABLE_TEMPORARY = "ServiceUnavailableTemporary";
    private final static String INTERNAL_FAILURE = "InternalFailure";

    @Test
    public void setJudgeNeedBackoff(){
        assertTrue(BackoffUtils.judgeNeedBackoff(new ClientException(REJECTED_THROTTLING, "test Error")));
        assertTrue(BackoffUtils.judgeNeedBackoff(new ClientException(SERVICE_UNAVAILABLE_TEMPORARY, "test Error")));
        assertTrue(BackoffUtils.judgeNeedBackoff(new ClientException(INTERNAL_FAILURE, "test Error")));
        assertFalse(BackoffUtils.judgeNeedBackoff(new ClientException("test Error", "test Error")));
    }
}
