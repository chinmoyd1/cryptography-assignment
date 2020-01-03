package com.psl.cryptography.assignment.service.sign.sha_rsa;


import com.psl.cryptography.assignment.service.sign.Sign;
import com.psl.cryptography.assignment.service.sign.SignFactory;
import org.junit.Before;
import org.junit.Test;

import java.security.*;
import java.util.Base64;

import static org.junit.Assert.*;

public class SHA_RSATest {

    Sign sha_rsa;
    KeyPair keyPair;
    String data;
    String digitalSignature;

    @Before
    public void setUp() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        data = "Confidential";
        sha_rsa = SignFactory.getHashSign("SHA_RSA");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        Base64.Encoder encoder = Base64.getEncoder();
        digitalSignature = encoder.encodeToString(signature.sign());
    }

    @Test
    public void sign() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String digitalSign = sha_rsa.sign(data,keyPair.getPrivate());
        assertNotNull(digitalSign);
    }

    @Test
    public void verify() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        boolean verified = sha_rsa.verify(data.getBytes(),digitalSignature.getBytes(),keyPair.getPublic());
        assertTrue(verified);
    }
}