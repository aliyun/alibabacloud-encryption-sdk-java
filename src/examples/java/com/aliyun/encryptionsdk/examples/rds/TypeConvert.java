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

package com.aliyun.encryptionsdk.examples.rds;

import com.aliyun.encryptionsdk.exception.AliyunException;

import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class TypeConvert {

    public static byte[] charToBytes(char data) {
        return new byte[]{
                (byte) (data & 0xff),
                (byte) ((data >> 8) & 0xff)
        };
    }

    public static char bytesToChar(byte[] bytes) {
        return (char) (bytes[0] & 0xFF | (bytes[1] & 0xFF) << 8);
    }

    public static byte[] shortToBytes(short data) {
        return new byte[]{
                (byte) (data & 0xff),
                (byte) ((data >> 8) & 0xff)
        };
    }

    public static short bytesToShort(byte[] bytes) {
        return (short) (bytes[0] & 0xFF | (bytes[1] & 0xFF) << 8);
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

    public static byte[] longToBytes(long data) {
        return new byte[]{
                (byte) (data & 0xff),
                (byte) ((data >> 8) & 0xff),
                (byte) ((data >> 16) & 0xff),
                (byte) ((data >> 24) & 0xff),
                (byte) ((data >> 32) & 0xff),
                (byte) ((data >> 40) & 0xff),
                (byte) ((data >> 48) & 0xff),
                (byte) ((data >> 56) & 0xff),
        };
    }

    public static long bytesToLong(byte[] bytes) {
        return ((long) bytes[0] & 0xFF) |
                ((long) (bytes[1] & 0xFF) << 8) |
                ((long) (bytes[2] & 0xFF) << 16) |
                ((long) (bytes[3] & 0xFF) << 24) |
                ((long) (bytes[4] & 0xFF) << 32) |
                ((long) (bytes[5] & 0xFF) << 40) |
                ((long) (bytes[6] & 0xFF) << 48) |
                ((long) (bytes[7] & 0xFF) << 56);
    }

    public static byte[] floatToBytes(float data) {
        int intBits = Float.floatToIntBits(data);
        return intToBytes(intBits);
    }

    public static float bytesToFloat(byte[] bytes) {
        return Float.intBitsToFloat(bytesToInt(bytes));
    }

    public static byte[] doubleToBytes(double data) {
        long longBits = Double.doubleToLongBits(data);
        return longToBytes(longBits);
    }

    public static double bytesToDouble(byte[] bytes) {
        long l = bytesToLong(bytes);
        return Double.longBitsToDouble(l);
    }

    public static byte[] booleanToBytes(boolean data) {
        return new byte[]{(byte) (data ? 0x01 : 0x00)};
    }

    public static boolean bytesToBoolean(byte[] bytes) {
        return bytes[0] != 0x00;
    }

    public static byte[] byteToBytes(byte data) {
        return new byte[] {data};
    }

    public static byte bytesTobyte(byte[] bytes) {
        return bytes[0];
    }

    public static byte[] stringToBytes(String data, Charset charset) {
        return data.getBytes(charset);
    }

    public static String bytesToString(byte[] bytes, Charset charset) {
        return new String(bytes, charset);
    }

    public static Object convertToObject(byte[] bytes, Type clazz) {
        if (clazz == String.class) {
            return bytesToString(bytes, StandardCharsets.UTF_8);
        } else if (clazz == boolean.class) {
            return bytesToBoolean(bytes);
        } else if (clazz == char.class) {
            return bytesToChar(bytes);
        } else if (clazz == short.class) {
            return bytesToShort(bytes);
        } else if (clazz == int.class) {
            return bytesToInt(bytes);
        } else if (clazz == long.class) {
            return bytesToLong(bytes);
        } else if (clazz == float.class) {
            return bytesToFloat(bytes);
        } else if (clazz == double.class) {
            return bytesToDouble(bytes);
        } else if (clazz == byte.class){
            return bytesTobyte(bytes);
        } else {
            throw new AliyunException("Type conversion failed");
        }
    }

    public static byte[] convertToBytes(Object object) {
        if (object instanceof String) {
            return stringToBytes((String) object, StandardCharsets.UTF_8);
        } else if (object instanceof Boolean) {
            return booleanToBytes((Boolean) object);
        }  else if (object instanceof Character) {
            return charToBytes((Character) object);
        } else if (object instanceof Short){
            return shortToBytes((Short) object);
        } else if (object instanceof Integer) {
            return intToBytes((Integer) object);
        } else if (object instanceof Long) {
            return longToBytes((Long) object);
        } else if (object instanceof Float) {
            return floatToBytes((Float) object);
        } else if (object instanceof Double) {
            return doubleToBytes((Double) object);
        } else if (object instanceof Byte){
            return byteToBytes((Byte) object);
        } else {
            throw new AliyunException("Type conversion failed");
        }
    }
}
