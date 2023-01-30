English | [简体中文](README-CN.md)

![](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

## AlibabaCloud Encryption SDK for Java

Alibaba Cloud Encryption SDK supports data encryption and decryption on the client side. You can use this SDK with Alibaba Cloud [Key Management Service (KMS)](https://www.aliyun.com/product/kms) to encrypt data, decrypt data, sign signatures and verify signatures.

When you use Alibaba Cloud Encryption SDK with KMS, you need only to focus on data encryption, data decryption, signing and verification. This reduces the costs that are required to ensure the security, integrity, and availability of your keys.

The SDK provides the following features:

- Data encryption, data decryption, signing and verification
- Generation and protection of data keys (In this case, you must use the SDK with KMS.)
- Customization of formats for encrypted data

Before you encrypt and decrypt data, you must use Alibaba Cloud Encryption SDK to create a data key provider and use KMS to create a customer master key (CMK).

### Encryption process

1. Create a CMK by using the KMS console or by calling the [CreateKey](https://help.aliyun.com/document_detail/28947.html) operation.
2. Initialize the DataKeyProvider instance and specify the Alibaba Cloud Resource Name (ARN) of the CMK that you created.
3. Call the Encrypt operation to encrypt data. During the encryption process, [DefaultDataKeyProvider](https://github.com/aliyun/alibabacloud-encryption-sdk-java/src/main/java/com/aliyun/encryptionsdk/provider/dataKey/DefaultDataKeyProvider.java) calls the [GenerateDataKey](https://help.aliyun.com/document_detail/28948.html) operation of KMS to create a data key. Then, DefaultDataKeyProvider encrypts data by using the data key.

#### Format of the encryption result

The encryption result is returned as a message that consists of a header and a body. The message is encoded by using Abstract Syntax Notation One (ASN.1). The header contains information such as encryption context and data key ciphertext. The body consists of the initialization vector (IV), ciphertext, and authentication information.

```asn1
EncryptionMessage ::== SEQUENCE {
	encryptionHead        EncryptionHead    ---The header of the message header.
	encryptionBody        EncryptionBody    --The body of the message.
}
EncryptionHead ::== SEQUENCE {
	version               INTEGER                 --The version.
	algorithm             INTEGER                 --The algorithm.
	encryptedDataKeys     SET EncryptedDataKey    --The list of data key cyphertext.
	encryptionContext     SET EncryptionContext   --The encryption context.
	headerIv              OCTECT STRING           --The initialization vector (IV) for header authentication.
	headerAuthTag         OCTECT STRING           --The header authentication information.
}
EncryptionBody ::== SEQUENCE{
	iv                    OCTECT STRING           --The initialization vector.
	cipherText            OCTECT STRING           --The cyphertext.
	authTag               OCTECT STRING           --The authentication data when Galois/Counter Mode is used.
}
```

### Signature generation and verification

Signature generation and verification is implemented based on public-key cryptography. The signer uses the private key that matches a public key to sign data. Then, the signer sends the data and signature to the message receiver. The message receiver uses the public key to verify the received signature.

Signature generation and verification is widely used to ensure information security and defend against forgery, repudiation, impersonation, and tampering. The signature feature of Alibaba Cloud Encryption SDK is provided based on the signature feature of KMS.

To sign data, perform the following steps:

1. Create an asymmetric [CMK](https://help.aliyun.com/document_detail/148147.html) for signature verification in KMS.
2. Specify the KeyId and KeyVersionId of the CMK in [KmsAsymmetricKeyProvider](https://github.com/aliyun/alibabacloud-encryption-sdk-java/src/main/java/com/aliyun/encryptionsdk/provider/KmsAsymmetricKeyProvider.java).
3. Call the Sign operation of Alibaba Cloud Encryption SDK to sign data.

### Compilation

```shell
$ git clone https://github.com/aliyun/alibabacloud-encryption-sdk-java.git
$ cd alibabacloud-encryption-sdk-java
$ mvn package -DskipTests
```

### Maven dependency

```xml
<dependency>
  <groupId>com.aliyun</groupId>
  <artifactId>alibabacloud-encryption-sdk-java</artifactId>
  <version>1.1.0</version>
</dependency>
```

### Code example
#### 1. kms example
```java
public class BasicEncryptionExample {
    private static final String ACCESS_KEY_ID = System.getenv("<AccessKeyId>");
    private static final String ACCESS_KEY_SECRET = System.getenv("<AccessKeySecret>");
    private static final String CMK_ARN = "acs:kms:RegionId:UserId:key/CmkId";
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(StandardCharsets.UTF_8);
    private static final List<String> CMK_ARN_LIST;
    static {
        CMK_ARN_LIST = new ArrayList<>();
        CMK_ARN_LIST("cmk1");
        CMK_ARN_LIST("cmk2");
    }

    public static void main(String[] args) {
        // 1. Configure parameters to access kms.
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);

        // 2. Create an SDK object and specify the parameters that are used to access Alibaba Cloud.
        AliyunCrypto aliyunSDK = new AliyunCrypto(config);
        // Set cache CryptoKeyManager. This parameter is optional. If you do not specify this parameter, DefaultCryptoKeyManager is used.
        //aliyunSDK.setCryptoKeyManager(new CachingCryptoKeyManager(new LocalDataKeyMaterialCache()));

        // 3. Create a data key provider for your data key or signature.
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(CMK_ARN);
        // Configure the algorithm. This parameter is optional. If you do not specify this parameter, AES_GCM_NOPADDING_256 is used.
        //provider.setAlgorithm(CryptoAlgorithm.SM4_GCM_NOPADDING_128);
        // Specify multiple CMKs. This parameter is optional. By default, only one CMK is used.
        //provider.setMultiCmkId(CMK_ARN_LIST);
        // Create data key providers.
        //BaseDataKeyProvider provider = new SecretManagerDataKeyProvider(CMK_ID, "dataKeySecretName");

        // 4. Specify the encryption context.
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("one", "one");
        encryptionContext.put("two", "two");

        // 5. Call the Encrypt operation.
        CryptoResult<byte[]> cipherResult = aliyunSDK.encrypt(provider, PLAIN_TEXT, encryptionContext);
        CryptoResult<byte[]> plainResult = aliyunSDK.decrypt(provider, cipherResult.getResult());

        Assert.assertArrayEquals(PLAIN_TEXT, plainResult.getResult());
    }
}
```
#### 2. dkms example
```java
import com.aliyun.dkms.gcs.openapi.models.Config;
import com.aliyun.encryptionsdk.model.CryptoResult;
import com.aliyun.encryptionsdk.model.DkmsConfig;
import com.aliyun.encryptionsdk.provider.BaseDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.DefaultDataKeyProvider;
import org.junit.Assert;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BasicEncryptionExample {
    private static final String ACCESS_KEY_ID = System.getenv("<AccessKeyId>");
    private static final String ACCESS_KEY_SECRET = System.getenv("<AccessKeySecret>");
    private static final String CMK_ARN = "acs:kms:RegionId:UserId:key/CmkId";
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(StandardCharsets.UTF_8);
    private static final List<String> CMK_ARN_LIST;

    static {
        CMK_ARN_LIST = new ArrayList<>();
        CMK_ARN_LIST.add("cmk1");
        CMK_ARN_LIST.add("cmk2");
    }

    public static void main(String[] args) {
        // 1. Configure parameters to access dkms.
        AliyunKmsConfig config = new AliyunKmsConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        config.addDkmsConfig(new DkmsConfig(
                                new Config()
                                .setRegionId("<RegionId>")
                                .setClientKeyFile("<ClientKeyFile>")
                                .setPassword("<Password>")
                                .setEndpoint("<Endpoint>")
                                .setProtocol("<Protocol>")
                            , false));
        // 2. Create an SDK object and specify the parameters that are used to access Alibaba Cloud.
        AliyunCrypto aliyunSDK = new AliyunCrypto(config);
        // Set cache CryptoKeyManager. This parameter is optional. If you do not specify this parameter, DefaultCryptoKeyManager is used.
        //aliyunSDK.setCryptoKeyManager(new CachingCryptoKeyManager(new LocalDataKeyMaterialCache()));

        // 3. Create a data key provider for your data key or signature.
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(CMK_ARN);
        // Configure the algorithm. This parameter is optional. If you do not specify this parameter, AES_GCM_NOPADDING_256 is used.
        //provider.setAlgorithm(CryptoAlgorithm.SM4_GCM_NOPADDING_128);
        // Specify multiple CMKs. This parameter is optional. By default, only one CMK is used.
        //provider.setMultiCmkId(CMK_ARN_LIST);
        // Create data key providers.
        //BaseDataKeyProvider provider = new SecretManagerDataKeyProvider(CMK_ID, "dataKeySecretName");

        // 4. Specify the encryption context.
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("one", "one");
        encryptionContext.put("two", "two");

        // 5. Call the Encrypt operation.
        CryptoResult<byte[]> cipherResult = aliyunSDK.encrypt(provider, PLAIN_TEXT, encryptionContext);
        CryptoResult<byte[]> plainResult = aliyunSDK.decrypt(provider, cipherResult.getResult());

        Assert.assertArrayEquals(PLAIN_TEXT, plainResult.getResult());
    }
}
```
