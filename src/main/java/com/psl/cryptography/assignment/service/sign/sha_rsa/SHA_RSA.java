package com.psl.cryptography.assignment.service.sign.sha_rsa;

import com.psl.cryptography.assignment.service.sign.Sign;

import java.security.*;
import java.util.Base64;

public class SHA_RSA implements Sign {

    @Override
    public String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());

        byte[] signatureBytes = signature.sign();

        Base64.Encoder encoder = Base64.getEncoder();
        String digitalSignature = encoder.encodeToString(signatureBytes);

        return digitalSignature;
    }

    @Override
    public Boolean verify(byte[] message, byte[] digitalSign, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] originalDigitalSign = decoder.decode(digitalSign);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message);

        boolean isCorrect = signature.verify(originalDigitalSign);

        return isCorrect;
    }
}
