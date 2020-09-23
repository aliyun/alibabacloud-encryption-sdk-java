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

/**
 * 处理ClientException异常情况是否应该重试策略
 */
public class BackoffUtils {

    private final static String REJECTED_THROTTLING = "Rejected.Throttling";
    private final static String SERVICE_UNAVAILABLE_TEMPORARY = "ServiceUnavailableTemporary";
    private final static String INTERNAL_FAILURE = "InternalFailure";

    private BackoffUtils() {

    }

    public static boolean judgeNeedBackoff(ClientException e) {
        if (REJECTED_THROTTLING.equals(e.getErrCode()) || SERVICE_UNAVAILABLE_TEMPORARY.equals(e.getErrCode()) || INTERNAL_FAILURE.equals(e.getErrCode())) {
            return true;
        }
        return false;
    }
}
