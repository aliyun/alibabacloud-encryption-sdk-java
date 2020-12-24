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

import com.aliyun.encryptionsdk.exception.CipherTextParseException;
import com.aliyun.encryptionsdk.model.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Base64;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.aliyun.encryptionsdk.model.Constants.SDK_VERSION;

/**
 * {@link FormatHandler} 的ASN1数据格式实现
 */
public class Asn1FormatHandler implements FormatHandler {
    private static final Charset ASN1_ENCODING = StandardCharsets.UTF_8;

    private ASN1Sequence encryptionInfo;
    private ASN1Sequence encryptionHead;
    private ASN1Integer version;
    private ASN1Integer algorithm;
    private ASN1Set encryptedDataKeys;
    private ASN1Set encryptionContext;
    private DEROctetString headerIv;
    private DEROctetString headerAuthTag;
    private ASN1Sequence encryptionBody;
    private DEROctetString iv;
    private DEROctetString cipherText;
    private DEROctetString authTag;

    public Asn1FormatHandler() {}

    @Override
    public byte[] serialize(CipherMaterial cipherMaterial) {
        CipherHeader cipherHeader = cipherMaterial.getCipherHeader();
        CipherBody cipherBody = cipherMaterial.getCipherBody();
        if (cipherHeader != null) {
            this.version = new ASN1Integer(cipherHeader.getVersion());
            this.algorithm = new ASN1Integer(cipherHeader.getAlgorithm().getValue());
            this.encryptedDataKeys = combineEncryptedDataKeys(cipherHeader.getEncryptedDataKeys());
            this.encryptionContext = combineEncryptionContext(cipherHeader.getEncryptionContext());
            this.headerIv = new DEROctetString(cipherHeader.getHeaderIv());
            this.headerAuthTag = new DEROctetString(cipherHeader.getHeaderAuthTag());
            this.encryptionHead = combineEncryptionHead();
        }
        if (cipherBody != null) {
            this.iv = new DEROctetString(cipherBody.getIv());
            this.cipherText = new DEROctetString(cipherBody.getCipherText());
            this.authTag = new DEROctetString(cipherBody.getAuthTag());
            this.encryptionBody = combineEncryptionBody();
        }
        this.encryptionInfo = combineEncryptionInfo();
        return asn1ToBytes(encryptionInfo);
    }

    @Override
    public CipherMaterial deserialize(byte[] cipherData) {
        ASN1Sequence seq = (ASN1Sequence)bytesToAsn1(cipherData);

        if (seq.size() != 2) {
            throw new CipherTextParseException("Abnormal cipherData serialize");
        }
        encryptionInfo = seq;
        deserializeCipherHeader(seq.getObjectAt(0));
        deserializeCipherBody(seq.getObjectAt(1));

        CipherHeader cipherHeader = new CipherHeader(parseEncryptedDataKeys(encryptedDataKeys),
                parseEncryptionContext(encryptionContext), CryptoAlgorithm.getAlgorithm(this.algorithm.getValue().intValue()),
                headerIv.getOctets(), headerAuthTag.getOctets());
        CipherBody cipherBody = new CipherBody(iv.getOctets(), cipherText.getOctets(), authTag.getOctets());
        return new CipherMaterial(cipherHeader, cipherBody);
    }

    @Override
    public byte[] serializeCipherHeader(CipherHeader cipherHeader) {
        this.version = new ASN1Integer(cipherHeader.getVersion());
        this.algorithm = new ASN1Integer(cipherHeader.getAlgorithm().getValue());
        this.encryptedDataKeys = combineEncryptedDataKeys(cipherHeader.getEncryptedDataKeys());
        this.encryptionContext = combineEncryptionContext(cipherHeader.getEncryptionContext());
        this.headerIv = new DEROctetString(cipherHeader.getHeaderIv());
        this.headerAuthTag = new DEROctetString(cipherHeader.getHeaderAuthTag());
        this.encryptionHead = combineEncryptionHead();
        return asn1ToBytes(encryptionHead);
    }

    @Override
    public CipherHeader deserializeCipherHeader(byte[] cipherHeaderBytes) {
        ASN1Sequence seq = (ASN1Sequence)bytesToAsn1(cipherHeaderBytes);
        deserializeCipherHeader(seq);

        List<EncryptedDataKey> encryptedDataKeys = parseEncryptedDataKeys(this.encryptedDataKeys);
        Map<String,String> encryptionContext = parseEncryptionContext(this.encryptionContext);
        CryptoAlgorithm algorithm = CryptoAlgorithm.getAlgorithm(this.algorithm.getValue().intValue());
        return new CipherHeader(version.getValue().intValue(), encryptedDataKeys, encryptionContext, algorithm, headerIv.getOctets(), headerAuthTag.getOctets());
    }

    @Override
    public byte[] serializeCipherBody(CipherBody cipherBody) {
        this.iv = new DEROctetString(cipherBody.getIv());
        this.cipherText = new DEROctetString(cipherBody.getCipherText());
        this.authTag = new DEROctetString(cipherBody.getAuthTag());
        this.encryptionBody = combineEncryptionBody();
        return asn1ToBytes(encryptionBody);
    }

    @Override
    public CipherBody deserializeCipherBody(byte[] cipherBody) {
        ASN1Sequence seq = (ASN1Sequence)bytesToAsn1(cipherBody);
        deserializeCipherBody(seq);
        return new CipherBody(iv.getOctets(), cipherText.getOctets(), authTag.getOctets());
    }

    private byte[] asn1ToBytes(ASN1Object seq) {
        ASN1OutputStream aOu = null;
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()){
            aOu = ASN1OutputStream.create(outputStream);
            aOu.writeObject(seq);
            aOu.flush();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new CipherTextParseException("cipherData parsing failed", e);
        } finally {
            if (aOu != null) {
                try {
                    aOu.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private ASN1Object bytesToAsn1(byte[] bytes) {
        ASN1InputStream aIn = null;
        ASN1Object seq;
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes)) {
            aIn = new ASN1InputStream(inputStream);
            seq = aIn.readObject();
        } catch (IOException e) {
            throw new CipherTextParseException("cipherData parsing failed", e);
        } finally {
            if (aIn != null) {
                try {
                    aIn.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return seq;
    }

    private void deserializeCipherHeader(ASN1Encodable encodable) {
        ASN1Sequence head = (ASN1Sequence)encodable;
        encryptionHead = head;
        if (head.size() != 6) {
            throw new CipherTextParseException("Abnormal cipherText serialize");
        }
        version = (ASN1Integer)head.getObjectAt(0);
        algorithm = (ASN1Integer)head.getObjectAt(1);
        encryptedDataKeys = (ASN1Set) head.getObjectAt(2);
        encryptionContext = (ASN1Set)head.getObjectAt(3);
        headerIv = (DEROctetString) head.getObjectAt(4);
        headerAuthTag = (DEROctetString) head.getObjectAt(5);
    }

    private void deserializeCipherBody(ASN1Encodable encodable) {
        ASN1Sequence body = (ASN1Sequence)encodable;
        encryptionBody = body;
        if (body.size() != 3) {
            throw new CipherTextParseException("Abnormal cipherText serialize");
        }
        iv = (DEROctetString)body.getObjectAt(0);
        cipherText = (DEROctetString) body.getObjectAt(1);
        authTag = (DEROctetString) body.getObjectAt(2);
    }

    private ASN1Sequence combineEncryptionInfo() {
        ASN1EncodableVector infoVec = new ASN1EncodableVector();
        if (encryptionHead != null) {
            infoVec.add(encryptionHead);
        }
        if (encryptionBody != null) {
            infoVec.add(encryptionBody);
        }
        return new DERSequence(infoVec);
    }

    private ASN1Sequence combineEncryptionHead() {
        ASN1EncodableVector headVec = new ASN1EncodableVector();
        headVec.add(version);
        headVec.add(algorithm);
        headVec.add(encryptedDataKeys);
        headVec.add(encryptionContext);
        if (headerIv != null) {
            headVec.add(headerIv);
        }
        if (headerAuthTag != null) {
            headVec.add(headerAuthTag);
        }
        return new DERSequence(headVec);
    }

    private ASN1Sequence combineEncryptionBody() {
        ASN1EncodableVector bodyVec = new ASN1EncodableVector();
        bodyVec.add(iv);
        bodyVec.add(cipherText);
        bodyVec.add(authTag);
        return new DERSequence(bodyVec);
    }

    private ASN1Set combineEncryptedDataKeys(List<EncryptedDataKey> encryptedDataKeys) {
        ASN1EncodableVector dataKeyVec = new ASN1EncodableVector();
        encryptedDataKeys.forEach(dataKey -> {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new DEROctetString(dataKey.getKeyId()));
            vector.add(new DEROctetString(Base64.decode(dataKey.getDataKey())));
            dataKeyVec.add(new DERSequence(vector));
        });
        return new DERSet(dataKeyVec);
    }

    private List<EncryptedDataKey> parseEncryptedDataKeys(ASN1Set set) {
        List<EncryptedDataKey> list = new ArrayList<>();
        for (ASN1Encodable aSet : set) {
            DLSequence sequence = (DLSequence) aSet;
            ASN1OctetString key = (DEROctetString) sequence.getObjectAt(0);
            ASN1OctetString dataKey = (DEROctetString) sequence.getObjectAt(1);
            list.add(new EncryptedDataKey(key.getOctets(), Base64.encode(dataKey.getOctets())));
        }
        return list;
    }

    private ASN1Set combineEncryptionContext(Map<String,String> encryptionContext) {
        ASN1EncodableVector contextVec = new ASN1EncodableVector();
        encryptionContext.forEach((key, value) -> {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new DEROctetString(key.getBytes(ASN1_ENCODING)));
            vector.add(new DEROctetString(value.getBytes(ASN1_ENCODING)));
            contextVec.add(new DERSequence(vector));
        });
        return new DERSet(contextVec);
    }

    private Map<String,String> parseEncryptionContext(ASN1Set set) {
        Map<String, String> map = new HashMap<>();
        for (ASN1Encodable aSet : set) {
            DLSequence sequence = (DLSequence) aSet;
            ASN1OctetString key = (DEROctetString) sequence.getObjectAt(0);
            ASN1OctetString value = (DEROctetString) sequence.getObjectAt(1);
            map.put(new String(key.getOctets(), ASN1_ENCODING), new String(value.getOctets(), ASN1_ENCODING));
        }
        return map;
    }

}
