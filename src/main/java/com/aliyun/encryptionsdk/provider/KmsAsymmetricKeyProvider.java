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

package com.aliyun.encryptionsdk.provider;

import com.aliyun.encryptionsdk.exception.AliyunException;
import com.aliyun.encryptionsdk.exception.InvalidAlgorithmException;
import com.aliyun.encryptionsdk.exception.InvalidArgumentException;
import com.aliyun.encryptionsdk.kms.AliyunKms;
import com.aliyun.encryptionsdk.logger.CommonLogger;
import com.aliyun.encryptionsdk.model.*;
import com.aliyuncs.utils.StringUtils;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECFieldElement;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 使用kms服务端的AsymmetricSign和AsymmetricVerify接口进行数据签名及验签
 */
public class KmsAsymmetricKeyProvider implements SignatureProvider {
    private AliyunKms kms;
    private CmkId keyId;
    private String keyVersionId;
    private PublicKey publicKey;
    private SignatureAlgorithm signatureAlgorithm;

    public KmsAsymmetricKeyProvider(String keyId, String keyVersionId, SignatureAlgorithm signatureAlgorithm) {
        if (StringUtils.isEmpty(keyId) || StringUtils.isEmpty(keyVersionId)) {
            throw new InvalidArgumentException("keyId and keyVersionId cannot be empty");
        }
        this.keyId = new CmkId(keyId);
        this.keyVersionId = keyVersionId;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public KmsAsymmetricKeyProvider(String publicKey, SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKey = parsePublicKey(publicKey, signatureAlgorithm);
    }

    public KmsAsymmetricKeyProvider(PublicKey publicKey, SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKey = publicKey;
    }

    public KmsAsymmetricKeyProvider(String certificate) {
        this.signatureAlgorithm = parseCertSigAlgName(certificate);
        this.publicKey = parseCertPublicKey(certificate);
    }

    @Override
    public SignatureMaterial sign(SignatureMaterial material) {
        material.setSignatureAlgorithm(signatureAlgorithm);
        return asymmetricSign(material);
    }

    private SignatureMaterial asymmetricSign(SignatureMaterial material) {
        byte[] digest = material.getDigest();
        if (digest == null || digest.length == 0) {
            digest = this.getDigest(material.getMessage());
        }
        AliyunKms.AsymmetricSignResult result = kms.asymmetricSign(keyId, keyVersionId, signatureAlgorithm, digest);
        material.setKeyId(result.getKeyId());
        material.setKeyVersionId(result.getKeyVersionId());
        material.setValue(result.getValue());
        return material;
    }

    @Override
    public VerifyMaterial verify(VerifyMaterial material) {
        material.setSignatureAlgorithm(signatureAlgorithm);
        if (keyId != null && keyVersionId != null) {
            return asymmetricVerify(material);
        }
        return localVerify(material);
    }

    @Override
    public void setAliyunKms(AliyunKms kms) {
        if (this.kms == null) {
            this.kms = kms;
        }
    }

    @Override
    public SignatureAlgorithm getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    private VerifyMaterial asymmetricVerify(VerifyMaterial material) {
        byte[] digest = material.getDigest();
        if (digest == null || digest.length == 0) {
            digest = this.getDigest(material.getMessage());
        }
        AliyunKms.AsymmetricVerifyResult result = kms.asymmetricVerify(keyId, keyVersionId, signatureAlgorithm, digest, material.getSignature());
        material.setKeyId(result.getKeyId());
        material.setKeyVersionId(result.getKeyVersionId());
        material.setValue(result.getValue());
        return material;
    }

    private VerifyMaterial localVerify(VerifyMaterial material) {
        String algorithm = material.getSignatureAlgorithm().getAlgorithm();
        byte[] signData = material.getSignature();
        Signature signature;
        try {
            switch (algorithm) {
                case "RSA_PSS_SHA_256":
                    signature = Signature.getInstance("RSASSA-PSS");
                    signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    signature.initVerify(publicKey);
                    signature.update(material.getMessage());
                    break;
                case "RSA_PKCS1_SHA_256":
                    signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(publicKey);
                    signature.update(material.getMessage());
                    break;
                case "SM2DSA":
                    Security.addProvider(new BouncyCastleProvider());
                    signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
                    signature.initVerify(publicKey);
                    signature.update(material.getMessage());
                    break;
                default:
                    throw new InvalidAlgorithmException(String.format("algorithm '%s' not support.", algorithm));
            }
            material.setValue(signature.verify(signData));
            return material;
        } catch (Exception e) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf("localVerify verify failed", e);
            throw new AliyunException("localVerify verify failed", e);
        }
    }

    public byte[] getDigest(byte[] content) {
        if (content == null) {
            throw new NullPointerException("content must not be null");
        }
        try {
            if ("SM2DSA".equals(signatureAlgorithm.getAlgorithm())) {
                if (publicKey == null) {
                    publicKey = parsePublicKey(kms.getPublicKey(keyId, keyVersionId), signatureAlgorithm);
                }
                return calcSM3Digest(publicKey, content);
            } else {
                return MessageDigest.getInstance(signatureAlgorithm.getDigestAlgorithm()).digest(content);
            }
        } catch (Exception e) {
            throw new AliyunException(e.getMessage(), e.getCause());
        }
    }

    private PublicKey parsePublicKey(String publicKey, SignatureAlgorithm signatureAlgorithm) {
        String publicKeyPem = publicKey;
        publicKeyPem = publicKeyPem.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceFirst("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replaceAll("\\s", "");
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyDer);
        try {
            if ("SM2DSA".equals(signatureAlgorithm.getAlgorithm())) {
                return KeyFactory.getInstance("EC", new BouncyCastleProvider()).generatePublic(keySpec);
            }
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf(String.format("publicKey parsing failed: %s", publicKey), e);
            throw new AliyunException("publicKey parsing failed: %s", e);
        }
    }

    private Certificate parseCertificate(String certificate) {
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8));
            CertificateFactory factory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            return factory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf(String.format("Certificate parsing failed: %s", certificate), e);
            throw new AliyunException(String.format("Certificate parsing failed: %s", certificate), e);
        }
    }

    private PublicKey parseCertPublicKey(String certificate) {
        X509Certificate x509Certificate = (X509Certificate) parseCertificate(certificate);
        return x509Certificate.getPublicKey();
    }

    private SignatureAlgorithm parseCertSigAlgName(String certificate) {
        X509Certificate x509Certificate = (X509Certificate) parseCertificate(certificate);
        String sigAlgName = x509Certificate.getSigAlgName();
        switch (sigAlgName) {
            case "SHA256WITHRSA":
            case "SHA256withRSA":
                return SignatureAlgorithm.RSA_PKCS1_SHA_256;
            case "SM3WITHSM2":
            case "SM3withSM2":
                return SignatureAlgorithm.SM2DSA;
            default:
                CommonLogger.getCommonLogger(Constants.MODE_NAME).errorf(String.format("signature algorithm '%s' not support.", sigAlgName));
                throw new InvalidAlgorithmException(String.format("signature algorithm '%s' not support.", sigAlgName));
        }
    }

    private byte[] calcSM3Digest(PublicKey pubKey, byte[] message) {
        X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
        BCECPublicKey localECPublicKey = (BCECPublicKey) pubKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);
        byte[] z = getZ(ecPublicKeyParameters, ecDomainParameters);
        Digest digest = new SM3Digest();
        digest.update(z, 0, z.length);
        digest.update(message, 0, message.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    private byte[] getZ(ECPublicKeyParameters ecPublicKeyParameters, ECDomainParameters ecDomainParameters) {
        Digest digest = new SM3Digest();
        digest.reset();

        String userID = "1234567812345678";
        addUserID(digest, userID.getBytes());

        addFieldElement(digest, ecDomainParameters.getCurve().getA());
        addFieldElement(digest, ecDomainParameters.getCurve().getB());
        addFieldElement(digest, ecDomainParameters.getG().getAffineXCoord());
        addFieldElement(digest, ecDomainParameters.getG().getAffineYCoord());
        addFieldElement(digest, ecPublicKeyParameters.getQ().getAffineXCoord());
        addFieldElement(digest, ecPublicKeyParameters.getQ().getAffineYCoord());

        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    private void addUserID(Digest digest, byte[] userID) {
        int len = userID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userID, 0, userID.length);
    }

    private void addFieldElement(Digest digest, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }
}
