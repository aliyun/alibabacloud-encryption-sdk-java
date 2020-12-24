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

package com.aliyun.encryptionsdk.stream;

import com.aliyun.encryptionsdk.exception.AliyunException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class CopyStreamUtil {
    private static final int MAX_READ_BYTES = 1024;

    private CopyStreamUtil(){

    }

    public static void copyIsToOs(InputStream inputStream, OutputStream outputStream) {
        try {
            byte[] readBytes = new byte[MAX_READ_BYTES];
            int readLen;
            while ((readLen = inputStream.read(readBytes)) != -1) {
                outputStream.write(readBytes, 0, readLen);
            }
            inputStream.close();
            outputStream.close();
        } catch (IOException e) {
            throw new AliyunException(e);
        }
    }

    public static byte[] intToBytes(int data) {
        return new byte[]{
                (byte) (data & 0xff),
                (byte) ((data >> 8) & 0xff),
                (byte) ((data >> 16) & 0xff),
                (byte) ((data >> 24) & 0xff),
        };
    }

    public static int bytesToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) |
                ((bytes[1] & 0xFF) << 8) |
                ((bytes[2] & 0xFF) << 16) |
                ((bytes[3] & 0xFF) << 24);
    }
}
