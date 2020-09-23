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

package com.aliyun.encryptionsdk.handler;

import com.aliyun.encryptionsdk.model.CipherBody;
import com.aliyun.encryptionsdk.model.CipherHeader;
import com.aliyun.encryptionsdk.model.CipherMaterial;

/**
 * 定义了 {@link CipherMaterial} 各部分数据的序列化和反序列化方法
 * {@link CipherMaterial} 由两部分组成，{@link CipherHeader} 和 {@link CipherBody}
 */
public interface FormatHandler {

    byte[] serialize(CipherMaterial cipherMaterial);

    CipherMaterial deserialize(byte[] cipherData);

    byte[] serializeCipherHeader(CipherHeader cipherHeader);

    CipherHeader deserializeCipherHeader(byte[] cipherHeader);

    byte[] serializeCipherBody(CipherBody cipherBody);

    CipherBody deserializeCipherBody(byte[] cipherBody);
}
