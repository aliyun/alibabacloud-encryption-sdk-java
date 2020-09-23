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

package com.aliyun.encryptionsdk.examples.csr;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.model.CmkId;
import com.aliyun.encryptionsdk.model.SignatureAlgorithm;
import com.aliyun.encryptionsdk.model.ContentType;
import com.aliyun.encryptionsdk.provider.KmsAsymmetricKeyProvider;
import com.aliyun.encryptionsdk.provider.SignatureProvider;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


/**
 * 生成证书请求CSR
 */
public class GenerateRSACSR {

    private static DefaultAcsClient kmsClient;
    private static AliyunCrypto aliyunCrypto;
    private static final String ACCESS_KEY_ID = "<AccessKeyId>";
    private static final String ACCESS_KEY_SECRET = "<AccessKeySecret>";

    static {
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey(ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        aliyunCrypto = new AliyunCrypto(config);
    }

    //实现KMS的ContentSigner构建器
    private static class KmsContentSignerBuilder implements ContentSigner {
        private DefaultAcsClient kmsClient;
        private String keyId;
        private String keyVersionId;
        private AlgorithmIdentifier sigAlgId;
        private ByteArrayOutputStream stream;

        KmsContentSignerBuilder(DefaultAcsClient kmsClient, String keyId, String keyVersionId, String signatureAlgorithm) {
            this.kmsClient = kmsClient;
            this.keyId = keyId;
            this.keyVersionId = keyVersionId;
            this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
            this.stream = new ByteArrayOutputStream();
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return this.sigAlgId;
        }

        @Override
        public OutputStream getOutputStream() {
            return this.stream;
        }

        @Override
        public byte[] getSignature() {
            try {
                return sign(this.keyId, this.keyVersionId, stream.toByteArray());
            } catch (Exception e) {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
            }
        }

        public byte[] sign(String keyId, String keyVersionId, byte[] message) {
            SignatureProvider keyProvider = new KmsAsymmetricKeyProvider(keyId, keyVersionId, SignatureAlgorithm.RSA_PKCS1_SHA_256);
            return aliyunCrypto.sign(keyProvider, message, ContentType.MESSAGE).getResult();
        }

    }

    private static DefaultAcsClient kmsClient(String regionId, String accessKeyId, String accessKeySecret, String endpoint, String ignoreSSLCerts) {
        if (endpoint != null) {
            DefaultProfile.addEndpoint(regionId, "Kms", endpoint);
        }
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        if (ignoreSSLCerts != null) {
            clientConfig.setIgnoreSSLCerts(Boolean.parseBoolean(ignoreSSLCerts));
        }
        profile.setHttpClientConfig(clientConfig);
        return new DefaultAcsClient(profile);
    }

    private static String getPublicKey(String keyId, String keyVersionId) throws ClientException {
        final GetPublicKeyRequest req = new GetPublicKeyRequest();
        req.setAcceptFormat(FormatType.JSON);
        req.setKeyId(keyId);
        req.setKeyVersionId(keyVersionId);
        GetPublicKeyResponse publicKeyRes = kmsClient.getAcsResponse(req);
        return publicKeyRes.getPublicKey();
    }

    private static String generateCSR(String keyId, String keyVersionId, String subjectName, List<String> nameList, String signatureAlgorithm) throws Exception {
        GeneralName[] gns = new GeneralName[nameList.size()];
        for (int i = 0; i < nameList.size(); i++) {
            gns[i] = new GeneralName(GeneralName.dNSName, nameList.get(i));
        }
        GeneralNames subjectAltName = new GeneralNames(gns);

        CmkId cmkId = new CmkId(keyId);
        //获取KMS RSA公钥
        String publicKeyPem = getPublicKey(cmkId.getRawKeyId(), keyVersionId);
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        //RSA PEM公钥转换为PublicKey结构
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));

        //创建CSR构建器
        PKCS10CertificationRequestBuilder p10Builder = new PKCS10CertificationRequestBuilder(new X500Name(subjectName), SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));

        //添加CSR扩展属性
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

        //创建KMS签名器
        ContentSigner signer = new KmsContentSignerBuilder(kmsClient, keyId, keyVersionId, signatureAlgorithm);

        //构建CSR
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter pem = new JcaPEMWriter(sw);) {
            pem.writeObject(csr);
            pem.flush();
            return sw.toString();
        }
    }

    private static void writeTextFile(String outFile, String content) throws IOException {
        File file = new File(outFile);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes());
        }
    }

    public static void main(String[] args) {
        String regionId = "cn-hangzhou"; //KMS服务区域，根据实际情况修改
        kmsClient = kmsClient(regionId, ACCESS_KEY_ID, ACCESS_KEY_SECRET, null, null);

        try {
            String keyId = "acs:kms:RegionId:UserId:key/CmkId";
            String keyVersionId = "keyVersionId";
            String subjectName = "CN=Test Certificate Request, O=Aliyun KMS, C=CN";
            String signatureAlgorithm = "SHA256withRSA";
            String outFile = "./test.csr";
            List<String> domain = new ArrayList<String>() {{
                add("test.com");
            }};

            //获取CSR
            String csr = generateCSR(keyId, keyVersionId, subjectName, domain, signatureAlgorithm);

            //输出到本地
            writeTextFile(outFile, csr);

        } catch (ClientException e) {
            System.out.println("Failed.");
            System.out.println("Error code: " + e.getErrCode());
            System.out.println("Error message: " + e.getErrMsg());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

