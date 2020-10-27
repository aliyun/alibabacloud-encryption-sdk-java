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

package com.aliyun.encryptionsdk.kms;

import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyuncs.AcsRequest;
import com.aliyuncs.AcsResponse;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.utils.StringUtils;
import com.google.gson.Gson;

import java.util.Base64;
import java.util.Map;

/**
 * {@link AliyunKms} 默认实现
 * 依赖aliyun-java-sdk-core和aliyun-java-sdk-kms两个jar包
 */
public class DefaultAliyunKms implements AliyunKms {
    /**
     * 加密配置信息，定义了访问kms所需的访问密钥信息，client访问异常的重试次数和回退策略
     */
    private AliyunConfig config;

    public DefaultAliyunKms(AliyunConfig config) {
        this.config = config;
    }

    @Override
    public GenerateDataKeyResult generateDataKey(CmkId keyId, CryptoAlgorithm algorithm, Map<String, String> context) {
        GenerateDataKeyRequest request = new GenerateDataKeyRequest();
        request.setKeyId(keyId.getRawKeyId());
        if(algorithm.getKeySpec().equals("SM4_128"))
                request.setNumberOfBytes(16);
        else
                request.setKeySpec(algorithm.getKeySpec());
        request.setKeySpec(algorithm.getKeySpec());
        Gson gson = new Gson();
        request.setEncryptionContext(context.isEmpty() ? null : gson.toJson(context));
        GenerateDataKeyResponse response = getResult(GenerateDataKeyResponse.class, request, keyId);
        return new GenerateDataKeyResult(keyId.getKeyId(), response.getKeyVersionId(),
                response.getPlaintext(), response.getCiphertextBlob());
    }

    @Override
    public DecryptDataKeyResult decryptDataKey(EncryptedDataKey encryptedDataKey, Map<String, String> context) {
        DecryptRequest request = new DecryptRequest();
        request.setCiphertextBlob(encryptedDataKey.getDataKeyString());
        Gson gson = new Gson();
        request.setEncryptionContext(context.isEmpty() ? null : gson.toJson(context));
        DecryptResponse response = getResult(DecryptResponse.class, request, new CmkId(encryptedDataKey.getKeyIdString()));
        return new DecryptDataKeyResult(response.getKeyId(), response.getKeyVersionId(), response.getPlaintext());
    }

    @Override
    public EncryptedDataKey encryptDataKey(CmkId keyId, String plaintext) {
        EncryptRequest request = new EncryptRequest();
        request.setKeyId(keyId.getRawKeyId());
        request.setPlaintext(plaintext);
        EncryptResponse response = getResult(EncryptResponse.class, request, keyId);
        return new EncryptedDataKey(keyId.getKeyId(), response.getCiphertextBlob());
    }

    @Override
    public EncryptedDataKey reEncryptDataKey(CmkId keyId, EncryptedDataKey encryptedDataKey, Map<String, String> context) {
        ReEncryptRequest request = new ReEncryptRequest();
        request.setCiphertextBlob(encryptedDataKey.getDataKeyString());
        Gson gson = new Gson();
        request.setSourceEncryptionContext(context.isEmpty() ? null : gson.toJson(context));
        request.setDestinationKeyId(keyId.getRawKeyId());
        request.setDestinationEncryptionContext(context.isEmpty() ? null : gson.toJson(context));
        ReEncryptResponse response = getResult(ReEncryptResponse.class, request, new CmkId(encryptedDataKey.getKeyIdString()));
        return new EncryptedDataKey(keyId.getKeyId(), response.getCiphertextBlob());
    }

    @Override
    public AsymmetricSignResult asymmetricSign(CmkId keyId, String keyVersionId, SignatureAlgorithm algorithm, byte[] digest) {
        final AsymmetricSignRequest req = new AsymmetricSignRequest();
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        req.setAcceptFormat(FormatType.JSON);
        req.setKeyId(keyId.getRawKeyId());
        req.setKeyVersionId(keyVersionId);
        req.setAlgorithm(algorithm.getAlgorithm());
        req.setDigest(base64Digest);
        AsymmetricSignResponse response = getResult(AsymmetricSignResponse.class, req, keyId);
        return new AsymmetricSignResult(response.getKeyId(), response.getKeyVersionId(), response.getValue());
    }

    @Override
    public AsymmetricVerifyResult asymmetricVerify(CmkId keyId, String keyVersionId, SignatureAlgorithm algorithm, byte[] digest,
                                                   byte[] signature) {
        final AsymmetricVerifyRequest req = new AsymmetricVerifyRequest();
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        String base64Signature = Base64.getEncoder().encodeToString(signature);
        req.setAcceptFormat(FormatType.JSON);
        req.setKeyId(keyId.getRawKeyId());
        req.setKeyVersionId(keyVersionId);
        req.setAlgorithm(algorithm.getAlgorithm());
        req.setDigest(base64Digest);
        req.setValue(base64Signature);
        AsymmetricVerifyResponse response = getResult(AsymmetricVerifyResponse.class, req, keyId);
        return new AsymmetricVerifyResult(response.getKeyId(), response.getKeyVersionId(), response.getValue());
    }

    @Override
    public CreateSecretResult createSecret(CmkId keyId, String secretName, String versionId, String secretData, String secretDataType) {
        CreateSecretRequest request = new CreateSecretRequest();
        request.setVersionId(versionId);
        request.setEncryptionKeyId(keyId.getRawKeyId());
        request.setSecretName(secretName);
        request.setSecretData(secretData);
        request.setSecretDataType(secretDataType);
        CreateSecretResponse response = getResult(CreateSecretResponse.class, request, keyId);
        return new CreateSecretResult(response.getArn(), response.getSecretName(), response.getVersionId());
    }

    @Override
    public GetSecretValueResult getSecretValue(CmkId keyId, String secretName) {
        GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretName(secretName);
        GetSecretValueResponse response = getResult(GetSecretValueResponse.class, request, keyId);
        return new GetSecretValueResult(response.getSecretName(), response.getSecretData(), response.getSecretDataType());
    }

    @Override
    public String getPublicKey(CmkId keyId, String keyVersionId) {
        final GetPublicKeyRequest request = new GetPublicKeyRequest();
        request.setAcceptFormat(FormatType.JSON);
        request.setKeyId(keyId.getRawKeyId());
        request.setKeyVersionId(keyVersionId);
        GetPublicKeyResponse response = getResult(GetPublicKeyResponse.class, request, keyId);
        return response.getPublicKey();
    }

    private <T extends AcsResponse> T getResult(Class<T> clz, AcsRequest<T> request, CmkId keyId) {
        if (StringUtils.isEmpty(keyId.getRegion())) {
            throw new AliyunException("region information not obtained");
        }
        IAcsClient client = AliyunKmsClientFactory.getClient(config, keyId.getRegion());

        int maxRetries = config.getMaxRetries();
        if (maxRetries <= 0) {
            maxRetries = 1;
        }
        for (int i = 0; i < maxRetries; i++) {
            try {
                AcsResponse response = client.getAcsResponse(request);
                return clz.cast(response);
            } catch (ClientException e) {
                CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("Request kms error", e);
                if (BackoffUtils.judgeNeedBackoff(e)) {//need retry
                    try {
                        Thread.sleep(config.getBackoffStrategy().getWaitTimeExponential(i + 1));
                    } catch (InterruptedException ignore) {
                    }
                } else {
                    throw new AliyunException(e.getMessage(), e);
                }
            }
        }
        CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("No results obtained after retrying " + maxRetries + " times");
        throw new AliyunException("No results obtained after retrying " + maxRetries + " times");
    }
}
