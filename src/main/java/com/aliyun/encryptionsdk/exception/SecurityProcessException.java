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

package com.aliyun.encryptionsdk.exception;

/**
 * 算法处理失败时抛出此异常
 */
public class SecurityProcessException extends AliyunException {
    public SecurityProcessException() {
        super();
    }

    public SecurityProcessException(String message) {
        super(message);
    }

    public SecurityProcessException(String message, Throwable cause) {
        super(message, cause);
    }
}
