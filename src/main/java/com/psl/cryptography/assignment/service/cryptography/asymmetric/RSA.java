package com.psl.cryptography.assignment.service.cryptography.asymmetric;

import com.psl.cryptography.assignment.service.cryptography.Cryptography;

import javax.crypto.*;
import java.security.*;
import java.util.Base64;

public class RSA implements Cryptography {

    Cipher cipher;
    KeyPairGenerator keyPairGenerator;

    public RSA() {
        try {
            cipher = Cipher.getInstance("RSA");
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    @Override
    public KeyPair generateKey() throws NoSuchAlgorithmException {
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return keyPair;
    }

    @Override
    public String encrypt(byte[] plainTextByte, Key secretKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        Base64.Encoder encoder = Base64.getEncoder();
        String encryptedText = encoder.encodeToString(encryptedByte);

        return encryptedText;
    }

    @Override
    public byte[] decrypt(String encryptedText, Key secretKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

        return decryptedByte;
    }
}
