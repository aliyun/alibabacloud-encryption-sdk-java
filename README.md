阿里云加密软件工具开发包(AlibabaCloud Encryption SDK)是一个客户端密码库，通过与阿里云[密钥管理服务(KMS)](https://www.aliyun.com/product/kms)相结合，可以帮助用户快速实现数据的加解密、签名验签功能。

借助AlibabaCloud Encryption SDK和密钥管理服务(KMS)，您可以专注于数据加解密、电子签名验签等业务功能，无需花费大量成本来保障密钥的保密性、完整性和可用性。
阿里云Encryption SDK具有以下功能：
- 数据加解密、签名验签功能
- 借助阿里云KMS生成和保护数据密钥
- 自定义的加密数据格式

通过阿里云Encryption SDK，定一个DataKeyProvider，设置相应的KMS 用户主密钥(CMK)，就可以对数据进行加解密操作。

### 加密流程

1. 通过KMS控制台，或者调用[CreateKey](https://help.aliyun.com/document_detail/28947.html)接口，创建一个用户主密钥；
2. 创建DataKeyProvider，设置主密钥ARN；
3. 调用encrypt接口进行加密，加密过程中，会通过[DefaultDataKeyProvider](https://github.com/aliyun/alibabacloud-encryption-sdk-java/src/main/java/com/aliyun/encryptionsdk/provider/dataKey/DefaultDataKeyProvider.java)调用KMS的[GenerateDataKey](https://help.aliyun.com/document_detail/28948.html)接口创建一个数据密钥，得到数据密钥后对数据进行加密；

#### 加密结果消息格式
加密结果包含头部和消息体，使用ASN.1编码。消息头部包含加密上下文(Encryption Context)和数据密钥密文等信息，消息体包含IV、密文、和认证信息三部分。
```
EncryptionMessage ::== SEQUENCE {
	encryptionHead        EncryptionHead    --加密消息头
	encryptionBody        EncryptionBody    --加密消息体
}
EncryptionHead ::== SEQUENCE {
	version               INTEGER                 --版本
	algorithm             INTEGER                 --算法
	encryptedDataKeys     SET EncryptedDataKey    --DataKey加密集合
	encryptionContext     SET EncryptionContext   --加密上下文
	headerIv              OCTECT STRING           --头部认证向量
	headerAuthTag         OCTECT STRING           --头部认证信息
}
EncryptionBody ::== SEQUENCE{
	iv                    OCTECT STRING           --初始向量
	cipherText            OCTECT STRING           --密文
	authTag               OCTECT STRING           --GCM认证信息
}
```

### 数据签名验签

数据签名验签基于公钥密码技术，通过签名者拥有的私钥对数据进行签名，验签者使用公钥对签名信息进行验证。数字签名机制作为保障网络信息安全的手段之一，可以解决伪造、抵赖、冒充和篡改问题。
阿里云Encryption SDK的签名功能基于阿里云密钥管理服务(KMS)的签名服务。使用时，在阿里云KMS创建一个用于签名验签功能的[非对称用户主密钥(CMK)](https://help.aliyun.com/document_detail/148147.html)，在[KmsAsymmetricKeyProvider](https://github.com/aliyun/alibabacloud-encryption-sdk-java/src/main/java/com/aliyun/encryptionsdk/provider/KmsAsymmetricKeyProvider.java)中指定用户主密钥的KeyId和KeyVersionId，调用阿里云Encryption SDK提供的sign接口，可实现数据的签名功能。



### 构建
----
```
$ git clone https://github.com/aliyun/alibabacloud-encryption-sdk-java.git
$ cd alibabacloud-encryption-sdk-java
$ mvn package -DskipTests
```

### maven应用

```
<dependency>
  <groupId>com.aliyun</groupId>
  <artifactId>alibabacloud-encryption-sdk-java</artifactId>
  <version>1.0.3</version>
</dependency>
```

### 快速入门

```
public class BasicEncryptionExample {
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    private static final String CMK_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(StandardCharsets.UTF_8);
    private static final List<String> KEY_ID_LIST;
    static {
        KEY_ID_LIST = new ArrayList<>();
        KEY_ID_LIST.add("cmk1");
        KEY_ID_LIST.add("cmk2");
    }

    public static void main(String[] args) {
        //1.创建访问aliyun配置
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);

        //2.创建SDK，传入访问aliyun配置
        AliyunCrypto aliyunSDK = new AliyunCrypto(config);
        //设置缓存ckm（可设置，默认为DefaultCryptoKeyManager）
        //aliyunSDK.setCryptoKeyManager(new CachingCryptoKeyManager(new LocalDataKeyMaterialCache()));

        //3.创建provider，用于提供数据密钥或签名
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(CMK_ID);
        //设置不同的算法（可设置，默认为AES_GCM_NOPADDING_256）
        //provider.setAlgorithm(CryptoAlgorithm.SM4_GCM_NOPADDING_128);
        //设置多CMK（可设置，默认为单CMK）
        //provider.setMultiCmkId(KEY_ID_LIST);
        //创建不同的provider
        //BaseDataKeyProvider provider = new SecretManagerDataKeyProvider(CMK_ID, "dataKeySecretName");

        //4.加密上下文
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("one", "one");
        encryptionContext.put("two", "two");

        //5.调用加密接口
        CryptoResult<byte[]> cipherResult = aliyunSDK.encrypt(provider, PLAIN_TEXT, encryptionContext);
        CryptoResult<byte[]> plainResult = aliyunSDK.decrypt(provider, cipherResult.getResult());

        Assert.assertArrayEquals(PLAIN_TEXT, plainResult.getResult());
    }
}
```2