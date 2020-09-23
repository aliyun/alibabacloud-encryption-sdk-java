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

package com.aliyun.encryptionsdk;

import com.aliyun.encryptionsdk.model.ContentType;
import com.aliyun.encryptionsdk.model.SignatureAlgorithm;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.KmsAsymmetricKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.SecretManagerDataKeyProvider;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class AliyunCryptoTest {
    private AliyunCrypto aliyunCrypto;
    private AliyunConfig config;

    @Before
    public void setUp() {
        this.config = TestAccount.AliyunKMS.ENCRYPTION_CONFIG;
        this.aliyunCrypto = new AliyunCrypto(config);
    }

    @Test
    public void encryptDecrypt() {
        //用户的arn形式key
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String plaintext = "this is test.";

        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(keyId);

        final byte[] cipherText = this.aliyunCrypto.encrypt(dataKeyProvider,
                plaintext.getBytes(), Collections.emptyMap()).getResult();
        final byte[] decryptResult = this.aliyunCrypto.decrypt(dataKeyProvider, cipherText).getResult();

        assertArrayEquals(plaintext.getBytes(), decryptResult);

    }

    @Test
    public void singleRegionMultiCmkEncryptDecrypt() {
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String plaintext = "this is test.";
        List<String> keyIds = new ArrayList<String>();
        keyIds.add("acs:kms:RegionId:UserId:key/CmkId");
        keyIds.add("acs:kms:RegionId:UserId:key/CmkId");

        // 单region多CMK加密
        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(keyId);
        dataKeyProvider.setMultiCmkId(keyIds);

        final byte[] cipherText = this.aliyunCrypto.encrypt(dataKeyProvider,
                plaintext.getBytes(), Collections.emptyMap()).getResult();

        // 使用其他CMK解密
        String otherKeyId = "acs:kms:RegionId:UserId:key/CmkId";
        BaseDataKeyProvider otherDataKeyProvider = new DefaultDataKeyProvider(otherKeyId);
        final byte[] decryptResult = this.aliyunCrypto.decrypt(otherDataKeyProvider, cipherText).getResult();

        assertArrayEquals(plaintext.getBytes(), decryptResult);

    }

    @Test
    public void multiRegionMultiCmkEncryptDecrypt() {
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String plaintext = "this is test.";
        List<String> keyIds = new ArrayList<String>();
        keyIds.add("acs:kms:RegionId:UserId:key/CmkId");
        keyIds.add("acs:kms:RegionId:UserId:key/CmkId");

        // 多region多CMK加密
        BaseDataKeyProvider dataKeyProvider = new DefaultDataKeyProvider(keyId);
        dataKeyProvider.setMultiCmkId(keyIds);

        final byte[] cipherText = this.aliyunCrypto.encrypt(dataKeyProvider,
                plaintext.getBytes(), Collections.emptyMap()).getResult();

        // 使用cn-shanghai region CMK解密
        String shanghaiKeyId = "acs:kms:RegionId:UserId:key/CmkId";
        BaseDataKeyProvider shanghaiDataKeyProvider = new DefaultDataKeyProvider(shanghaiKeyId);
        final byte[] shanghaiDecryptResult = this.aliyunCrypto.decrypt(shanghaiDataKeyProvider, cipherText).getResult();

        assertArrayEquals(plaintext.getBytes(), shanghaiDecryptResult);

        // 使用cn-beijing region CMK解密
        String beijingKeyId = "acs:kms:RegionId:UserId:key/CmkId";
        BaseDataKeyProvider beijingDataKeyProvider = new DefaultDataKeyProvider(beijingKeyId);
        final byte[] beijingDecryptResult = this.aliyunCrypto.decrypt(beijingDataKeyProvider, cipherText).getResult();

        assertArrayEquals(plaintext.getBytes(), beijingDecryptResult);

    }

    @Test
    public void signVerify() {
        // RSA非对称密钥签名验签，keySpec=RSA_2048，keyUsage=SIGN/VERIFY
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String keyVersionId = "keyVersionId";
        byte[] msg = "this is test.".getBytes();

        SignatureProvider provider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.RSA_PKCS1_SHA_256);

        // 使用原始消息
        byte[] signature = aliyunCrypto.sign(provider, msg, ContentType.MESSAGE).getResult();
        Boolean isOk = aliyunCrypto.verify(provider, msg, signature, ContentType.MESSAGE).getResult();
        assertTrue(isOk);

        // 使用消息摘要
        byte[] sha256Digest = hex2Bytes("FECC75FE2A23D8EAFBA452EE0B8B6B56BECCF52278BF1398AADDEECFE0EA0FCE");
        signature = aliyunCrypto.sign(provider, sha256Digest, ContentType.DIGEST).getResult();
        isOk = aliyunCrypto.verify(provider, sha256Digest, signature, ContentType.DIGEST).getResult();
        assertTrue(isOk);

        // SM2非对称密钥签名验签，keySpec=EC_SM2，keyUsage=SIGN/VERIFY
        keyId = "acs:kms:RegionId:UserId:key/CmkId";
        keyVersionId = "keyVersionId";
        provider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.SM2DSA);

        // 使用原始消息
        signature = aliyunCrypto.sign(provider, msg, ContentType.MESSAGE).getResult();
        isOk = aliyunCrypto.verify(provider, msg, signature, ContentType.MESSAGE).getResult();
        assertTrue(isOk);

        // 使用消息摘要
        byte[] sm3Digest = hex2Bytes("6BCAADF4BE635BA03D88AC3FFA03E19F1907FCE5C07F3485DDF87444CEB5FEDC");
        signature = aliyunCrypto.sign(provider, sm3Digest, ContentType.DIGEST).getResult();
        isOk = aliyunCrypto.verify(provider, sm3Digest, signature, ContentType.DIGEST).getResult();
        assertTrue(isOk);
    }

    @Test
    public void rsaPublicKeyVerify() {
        // RSA非对称密钥签名验签，keySpec=RSA_2048，keyUsage=SIGN/VERIFY
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String keyVersionId = "keyVersionId";
        SignatureProvider provider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        byte[] msg = "this is test.".getBytes();

        // 使用KMS对消息进行签名
        byte[] signature = aliyunCrypto.sign(provider, msg, ContentType.MESSAGE).getResult();

        // 使用传入公钥方式进行验签
        String rsaPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvd9+hxVcGf20soetMjSH\n" +
                "9FvvirOyuESDIdEjwemXTK8LK5gR16gHhW9TvFncH6aQo5HQUdE/TNOQPcQLs1WT\n" +
                "4aAs1NW3QdO1JjVyzmtNMQCd9zVcE0GVkPXOwGx+uJ5ZPcz0sMODPxzKbSKiKan0\n" +
                "mQlJOEhzg+LOD5HSjy7vIapasRCju//QOMKvp9kP9QH9gfdP+jOVbPXLOFgZQDga\n" +
                "NaGOsuhYDw14a+PhQj2ylo7W7S6+csOLMu9zfJcgl5KM5Q/ZVpopxEd3ROHVhIBc\n" +
                "1PEdpEOkW/X5+J6BS74Wn25jm1YahRYmmrZrIs1v3clLLE3kn4eKKbhWht024CBg\n" +
                "8wIDAQAB\n" +
                "-----END PUBLIC KEY-----\n";
        provider = new KmsAsymmetricKeyProvider(rsaPublicKey, SignatureAlgorithm.RSA_PKCS1_SHA_256);
        Boolean isOk = aliyunCrypto.verify(provider, msg, signature, ContentType.MESSAGE).getResult();
        assertTrue(isOk);
    }

    @Test
    public void sm2PublicKeyVerify() {
        // SM2非对称密钥签名验签，keySpec=EC_SM2，keyUsage=SIGN/VERIFY
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String keyVersionId = "keyVersionId";
        byte[] msg = "this is test.".getBytes();

        SignatureProvider provider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.SM2DSA);

        // 使用KMS对消息进行签名
        byte[] signature = aliyunCrypto.sign(provider, msg, ContentType.MESSAGE).getResult();

        // 使用传入公钥方式进行验签
        String sm2PublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEXF1oHmE7SwQD/wN5SPT8bbkVY7Vr\n" +
                "4Bin+wsZ9YB/XHFBEUhFoKSQBRKwOVDmLZgEespX0SK4GVOXYV1VdD4+QQ==\n" +
                "-----END PUBLIC KEY-----\n";
        provider = new KmsAsymmetricKeyProvider(sm2PublicKey, SignatureAlgorithm.SM2DSA);
        Boolean isOk = aliyunCrypto.verify(provider, msg, signature, ContentType.MESSAGE).getResult();
        assertTrue(isOk);
    }

    @Test
    public void rsaCertVerify() {
        // RSA非对称密钥签名验签，keySpec=RSA_2048，keyUsage=SIGN/VERIFY
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String keyVersionId = "keyVersionId";
        byte[] msg = "this is test.".getBytes();

        SignatureProvider provider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.RSA_PKCS1_SHA_256);

        // 使用KMS对消息进行签名
        byte[] signature = aliyunCrypto.sign(provider, msg, ContentType.MESSAGE).getResult();

        // 使用传入证书方式进行验签
        String rsaCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDcDCCAlgCFAmA42kBFMk1kAfiKoIAJHwLmDtiMA0GCSqGSIb3DQEBCwUAMHwx\n" +
                "CzAJBgNVBAYTAmNuMQswCQYDVQQIDAJ6ajELMAkGA1UEBwwCaHoxDzANBgNVBAoM\n" +
                "BmFsaXl1bjEMMAoGA1UECwwDa21zMRQwEgYDVQQDDAtleGFtcGxlLmNvbTEeMBwG\n" +
                "CSqGSIb3DQEJARYPYWJjQGV4YW1wbGUuY29tMB4XDTIwMDcxNDA2MzUyNloXDTIx\n" +
                "MDcxNDA2MzUyNlowbTELMAkGA1UEBhMCQ04xJTAjBgNVBAMMHGVuY3J5cHRpb24t\n" +
                "c2RrLXJzYS1jZXJ0LXRlc3QxCzAJBgNVBAcMAmh6MQswCQYDVQQIDAJ6ajEPMA0G\n" +
                "A1UECgwGYWxpeXVuMQwwCgYDVQQLDANrbXMwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQC9336HFVwZ/bSyh60yNIf0W++Ks7K4RIMh0SPB6ZdMrwsrmBHX\n" +
                "qAeFb1O8WdwfppCjkdBR0T9M05A9xAuzVZPhoCzU1bdB07UmNXLOa00xAJ33NVwT\n" +
                "QZWQ9c7AbH64nlk9zPSww4M/HMptIqIpqfSZCUk4SHOD4s4PkdKPLu8hqlqxEKO7\n" +
                "/9A4wq+n2Q/1Af2B90/6M5Vs9cs4WBlAOBo1oY6y6FgPDXhr4+FCPbKWjtbtLr5y\n" +
                "w4sy73N8lyCXkozlD9lWminER3dE4dWEgFzU8R2kQ6Rb9fn4noFLvhafbmObVhqF\n" +
                "FiaatmsizW/dyUssTeSfh4opuFaG3TbgIGDzAgMBAAEwDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBAGf9+aZXoWgfkRN4/l4C0bKsdKR2oZk97gZbE95gcGONOGNSIk0NanJcAYVg\n" +
                "+z7zTh61Y+ncx8u6JZ7KRL5rkouwkNmh6X/jXHHEXlQ4XItiY5NMOIeCQgeuFsnr\n" +
                "TCpQ+4/nMJbEL4CtUmHt76T4cMFQjcbtMtRpckHc9/o74P0+trA/qYxmYjMYrkL0\n" +
                "iUar6OcP9QnjaIeCUGogtdcCe6p59rkO/kEHfGs2NgC/KjxKGpNMq/hBVgx0IgsI\n" +
                "U25ZtKLox1Imcb8TPHThn6ooQNkUI3DlwVN077C19ZvnUD1/IIwh5nn10Cuf6WfR\n" +
                "gfb813IMppKt7S7o3JIZUkNSukM=\n" +
                "-----END CERTIFICATE-----";
        provider = new KmsAsymmetricKeyProvider(rsaCert);
        Boolean isOk = aliyunCrypto.verify(provider, msg, signature, ContentType.MESSAGE).getResult();
        assertTrue(isOk);
    }

    @Test
    public void sm2CertVerify() {
        // SM2非对称密钥签名验签，keySpec=EC_SM2，keyUsage=SIGN/VERIFY
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String keyVersionId = "keyVersionId";
        byte[] msg = "this is test.".getBytes();

        SignatureProvider provider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.SM2DSA);

        // 使用KMS对消息进行签名
        byte[] signature = aliyunCrypto.sign(provider, msg, ContentType.MESSAGE).getResult();

        // 使用传入证书方式进行验签
        String sm2Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIB2jCCAX8CCQCLFKfzm5CyMTAKBggqgRzPVQGDdTB8MQswCQYDVQQGEwJjbjEL\n" +
                "MAkGA1UECAwCemoxCzAJBgNVBAcMAmh6MQ8wDQYDVQQKDAZhbGl5dW4xDDAKBgNV\n" +
                "BAsMA2ttczEUMBIGA1UEAwwLZXhhbXBsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Fi\n" +
                "Y0BleGFtcGxlLmNvbTAeFw0yMDA3MTQwMjUyMTdaFw0zMDA3MTIwMjUyMTdaMG0x\n" +
                "CzAJBgNVBAYTAkNOMSUwIwYDVQQDDBxlbmNyeXB0aW9uLXNkay1zbTItY2VydC10\n" +
                "ZXN0MQswCQYDVQQHDAJoejELMAkGA1UECAwCemoxDzANBgNVBAoMBmFsaXl1bjEM\n" +
                "MAoGA1UECwwDa21zMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEXF1oHmE7SwQD\n" +
                "/wN5SPT8bbkVY7Vr4Bin+wsZ9YB/XHFBEUhFoKSQBRKwOVDmLZgEespX0SK4GVOX\n" +
                "YV1VdD4+QTAKBggqgRzPVQGDdQNJADBGAiEA95AqSutw8i1TH88JJUu8+q5KkbUs\n" +
                "AkPVVO9+3/nxMfECIQDJ8x71bbN1TzXBtjPXIxOGcG3WY2/HH8rzLmiJvNAbzw==\n" +
                "-----END CERTIFICATE-----";
        provider = new KmsAsymmetricKeyProvider(sm2Cert);
        Boolean isOk = aliyunCrypto.verify(provider, msg, signature, ContentType.MESSAGE).getResult();
        assertTrue(isOk);
    }

    //非对称密钥加解密二期实现，该功能上线以后再测试
    public void asymmetricEncryptDecrypt() {
        //RSA非对称密钥加解密，keySpec=RSA_2048，keyUsage=ENCRYPT/DECRYPT
    }

    public static byte[] hex2Bytes(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String bytes2Hex(byte[] bytes) {
        final byte[] hexArray = "0123456789ABCDEF".getBytes();
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    @Test
    public void encryptDecryptSecretManagerDataKeyProvider() {
        String keyId = "acs:kms:RegionId:UserId:key/CmkId";
        String plaintext = "this is test.";
        String dataKeyId = "dataKey111";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");

        BaseDataKeyProvider provider = new SecretManagerDataKeyProvider(keyId, dataKeyId);

        byte[] encryptResult = aliyunCrypto.encrypt(provider, plaintext.getBytes(), encryptionContext).getResult();
        byte[] decryptResult = aliyunCrypto.decrypt(provider, encryptResult).getResult();

        assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decryptResult);
    }

}
