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

import com.aliyun.encryptionsdk.handler.AlgorithmHandler;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class CryptoInputStream extends InputStream {
    private InputStream inputStream;
    private AlgorithmHandler handler;
    private int encryptBlock;
    private boolean done = false;

    private ByteBuffer outByteBuffer = ByteBuffer.allocate(0);

    public CryptoInputStream(InputStream inputStream, AlgorithmHandler handler, int encryptBlock) {
        this.inputStream = inputStream;
        this.handler = handler;
        this.encryptBlock = encryptBlock;
    }

    private int processBytes() throws IOException {
        if (done) {
            return -1;
        } else {
            byte[] readBytes = new byte[encryptBlock];
            int readLen = inputStream.read(readBytes);

            if (readLen <= 0) {
                done = true;
                byte[] finalBytes = handler.doFinal();
                outByteBuffer = ByteBuffer.wrap(finalBytes);
            } else {
                byte[] processBytes = handler.update(readBytes, 0, readLen);
                if (processBytes == null) {
                    outByteBuffer = ByteBuffer.allocate(0);
                } else {
                    outByteBuffer = ByteBuffer.wrap(processBytes);
                }
            }

            return outByteBuffer.capacity();
        }
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (!outByteBuffer.hasRemaining()) {
            int readLen = 0;
            while (readLen == 0) {
                readLen = processBytes();
            }
            if (readLen < 0) {
                return -1;
            }
        }

        int copyLen = Math.min(len, outByteBuffer.remaining());
        outByteBuffer.get(b, 0, copyLen);
        return copyLen;
    }

    @Override
    public int read() throws IOException {
        if (!outByteBuffer.hasRemaining()) {
            int readLen = 0;
            while (readLen == 0) {
                readLen = processBytes();
            }
            if (readLen < 0) {
                return -1;
            }
        }

        return outByteBuffer.get() & 255;
    }

    @Override
    public int read(final byte[] b) throws IOException {
        return read(b, 0, b.length);
    }
}
