package com.psl.cryptography.assignment.service.cryptography.asymmetric;

import com.psl.cryptography.assignment.service.cryptography.CryptoFactory;
import com.psl.cryptography.assignment.service.cryptography.Cryptography;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class RSATest {

    Cryptography rsa;
    KeyPair keyPair;
    String secretString;
    String encryptedText;

    @Before
    public void setUp() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
        rsa = CryptoFactory.getCrypto("RSA");
        Cipher cipher = Cipher.getInstance("RSA");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

        secretString = "Confidential";
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] encryptedByte = cipher.doFinal(secretString.getBytes());
        Base64.Encoder encoder = Base64.getEncoder();
        encryptedText = encoder.encodeToString(encryptedByte);
    }

    @Test
    public void generateKey() throws NoSuchAlgorithmException {
        KeyPair kp = (KeyPair) rsa.generateKey();
        assertNotNull(kp.getPrivate());
        assertNotNull(kp.getPublic());
    }

    @Test
    public void encrypt() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        String encData = rsa.encrypt(secretString.getBytes(),keyPair.getPublic());
        assertNotNull(encData);
    }

    @Test
    public void decrypt() throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        byte[] decData = rsa.decrypt(encryptedText,keyPair.getPublic());
        assertEquals(secretString, new String(decData));
    }
}