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

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.model.*;
import com.aliyun.encryptionsdk.TestAccount;
import com.aliyun.encryptionsdk.TestFixtures;
import org.junit.Test;

import javax.crypto.Cipher;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class Asn1FormatHandlerTest {
    private final static  String PLAIN_TEXT = "this is test.";
    private static final Charset ENCODING = StandardCharsets.UTF_8;
    private static Asn1FormatHandler asn1FormatHandler = new Asn1FormatHandler();
    private static final AliyunCrypto DEFAULT_ALIYUN_CRYPTO = new AliyunCrypto(TestAccount.AliyunKMS.getAliyunConfig());

    @Test
    public void testAsn1ToBytesAndBytesToAsn1(){
        CipherMaterial cipherMaterial = createCipherMaterial();
        byte[] serialize = asn1FormatHandler.serialize(cipherMaterial);
        CipherMaterial deserialize = asn1FormatHandler.deserialize(serialize);
        TestFixtures.assertCipherMaterialEquals(cipherMaterial, deserialize);
    }

    @Test
    public void testSerialize(){
        CipherMaterial cipherMaterial = createCipherMaterial();

        byte[] cipherText = asn1FormatHandler.serialize(cipherMaterial);

        CryptoResult<byte[]> result = DEFAULT_ALIYUN_CRYPTO.decrypt(TestFixtures.createDefaultDataKeyProvider(), cipherText);
        assertArrayEquals(PLAIN_TEXT.getBytes(ENCODING), result.getResult());
    }

    @Test
    public void testDeserialize(){
        CipherMaterial cipherMaterial = createCipherMaterial();
        byte[] cipherBytes = asn1FormatHandler.serialize(cipherMaterial);
        CipherMaterial cipherMaterialParseResult = asn1FormatHandler.deserialize(cipherBytes);
        TestFixtures.assertCipherMaterialEquals(cipherMaterial, cipherMaterialParseResult);
    }

    @Test
    public void testSerializeDeserializeCipherHeader(){
        CipherMaterial cipherMaterial = createCipherMaterial();
        byte[] cipherHeaderBytes = asn1FormatHandler.serializeCipherHeader(cipherMaterial.getCipherHeader());
        CipherHeader cipherHeader = asn1FormatHandler.deserializeCipherHeader(cipherHeaderBytes);
        TestFixtures.assertCipherHeaderEquals(cipherMaterial.getCipherHeader(), cipherHeader);
    }

    @Test
    public void testSerializeDeserializeCipherBody(){
        CipherMaterial cipherMaterial = createCipherMaterial();
        byte[] cipherBodyBytes = asn1FormatHandler.serializeCipherBody(cipherMaterial.getCipherBody());
        CipherBody cipherBody = asn1FormatHandler.deserializeCipherBody(cipherBodyBytes);
        TestFixtures.assertCipherBodyEquals(cipherMaterial.getCipherBody(), cipherBody);
    }

    private CipherMaterial createCipherMaterial(){
        EncryptionMaterial encryptionMaterial = TestFixtures.createMaterialsResult(1);
        AlgorithmHandler handler = new AlgorithmHandler(encryptionMaterial.getAlgorithm(), encryptionMaterial.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        byte[] iv = new byte[encryptionMaterial.getAlgorithm().getIvLen()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        byte[] contentAad = null;
        if (encryptionMaterial.getAlgorithm().isWithAad()) {
            contentAad = TestFixtures.serializeContext(encryptionMaterial.getEncryptionContext());
        }
        byte[] result = handler.cipherData(iv, contentAad, PLAIN_TEXT.getBytes(ENCODING), 0, PLAIN_TEXT.length());

        CipherHeader cipherHeader = new CipherHeader(encryptionMaterial.getEncryptedDataKeys(), encryptionMaterial.getEncryptionContext(), encryptionMaterial.getAlgorithm());
        cipherHeader.calculateHeaderAuthTag(handler);

        int tagLen = cipherHeader.getAlgorithm().getTagLen();
        byte[] cipherText = new byte[result.length - tagLen];
        byte[] authTag = new byte[tagLen];
        if (tagLen != 0) {
            System.arraycopy(result, 0, cipherText, 0, result.length - tagLen);
            System.arraycopy(result, cipherText.length, authTag, 0, tagLen);
        } else {
            cipherText = result;
        }

        CipherBody cipherBody = new CipherBody(iv, cipherText, authTag);
        return new CipherMaterial(cipherHeader, cipherBody);
    }
}
