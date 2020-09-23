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

package com.aliyun.encryptionsdk.model;

public class CipherBody {
    private byte[] iv;
    private byte[] cipherText;
    private byte[] authTag;

    public CipherBody(byte[] iv, byte[] cipherText, byte[] authTag) {
        this.iv = iv;
        this.cipherText = cipherText;
        this.authTag = authTag;
    }

    public CipherBody(byte[] iv, byte[] cipherText) {
        this.iv = iv;
        this.cipherText = cipherText;
        this.authTag = new byte[0];
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getAuthTag() {
        return authTag;
    }
}
