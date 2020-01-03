package com.psl.cryptography.assignment.service.cryptography.symmetric;

import com.psl.cryptography.assignment.service.cryptography.CryptoFactory;
import com.psl.cryptography.assignment.service.cryptography.Cryptography;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.Assert.*;

public class AESTest {

    Cryptography aes;
    Cipher cipher;
    KeyGenerator keyGenerator;
    SecretKey aesSecretKey;
    String secretString;
    String encryptedText;

    @Before
    public void setUp() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        aes = CryptoFactory.getCrypto("AES");
        cipher = Cipher.getInstance("AES");
        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        aesSecretKey = keyGenerator.generateKey();

        secretString = "Confidential";
        cipher.init(Cipher.ENCRYPT_MODE, aesSecretKey);
        byte[] encryptedByte = cipher.doFinal(secretString.getBytes());
        Base64.Encoder encoder = Base64.getEncoder();
        encryptedText = encoder.encodeToString(encryptedByte);
    }

    @Test
    public void generateKey() throws NoSuchAlgorithmException {
        SecretKey secretKey = (SecretKey) aes.generateKey();
        assertNotNull(secretKey);
    }

    @Test
    public void encrypt() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        String data = "Confidential Data";
        String encData = aes.encrypt(data.getBytes(),aesSecretKey);
        assertNotNull(encData);
    }

    @Test
    public void decrypt() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        byte[] decData = aes.decrypt(encryptedText,aesSecretKey);
        assertEquals(secretString, new String(decData));
    }
}