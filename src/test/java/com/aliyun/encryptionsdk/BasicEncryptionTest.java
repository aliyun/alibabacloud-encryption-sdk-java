package com.aliyun.encryptionsdk;

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

public class BasicEncryptionTest {
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";
    private static final String CMK_ARN = "acs:kms:RegionId:UserId:key/CmkId";
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(StandardCharsets.UTF_8);
    private static final List<String> CMK_ARN_LIST;

    static {
        CMK_ARN_LIST = new ArrayList<>();
        CMK_ARN_LIST.add("cmk1");
        CMK_ARN_LIST.add("cmk2");
    }

    public static void main(String[] args) {
        //1. 创建可访问专属kms配置
        AliyunKmsConfig config = new AliyunKmsConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        config.addDkmsConfig(new DkmsConfig(
                new Config()
                        .setRegionId("<RegionId>")
                        .setClientKeyFile("<ClientKeyFile>")
                        .setPassword("<Password>")
                        .setEndpoint("<Endpoint>")
                        .setProtocol("<Protocol>"), false));
        // 2. 创建SDK，传入访问aliyun配置
        AliyunCrypto aliyunSDK = new AliyunCrypto(config);
        // 设置缓存ckm（可设置，默认为DefaultCryptoKeyManager）
        //aliyunSDK.setCryptoKeyManager(new CachingCryptoKeyManager(new LocalDataKeyMaterialCache()));
        // 3. 创建provider，用于提供数据密钥或签名
        BaseDataKeyProvider provider = new DefaultDataKeyProvider(CMK_ARN);
        // 设置不同的算法（可设置，默认为AES_GCM_NOPADDING_256）
        //provider.setAlgorithm(CryptoAlgorithm.SM4_GCM_NOPADDING_128);
        // 设置多CMK（可设置，默认为单CMK）
        //provider.setMultiCmkId(CMK_ARN_LIST);
        // 创建不同的provider
        //BaseDataKeyProvider provider = new SecretManagerDataKeyProvider(CMK_ID, "dataKeySecretName");

        // 4. 加密上下文
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("one", "one");
        encryptionContext.put("two", "two");

        // 5. 调用加密接口
        CryptoResult<byte[]> cipherResult = aliyunSDK.encrypt(provider, PLAIN_TEXT, encryptionContext);
        CryptoResult<byte[]> plainResult = aliyunSDK.decrypt(provider, cipherResult.getResult());

        Assert.assertArrayEquals(PLAIN_TEXT, plainResult.getResult());
    }
}
