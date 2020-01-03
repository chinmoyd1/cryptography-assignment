package com.psl.cryptography.assignment.service.cryptography.symmetric;

import com.psl.cryptography.assignment.service.cryptography.Cryptography;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES implements Cryptography {

    Cipher cipher;
    KeyGenerator keyGenerator;

    public AES() {
        try {
            cipher = Cipher.getInstance("AES");
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    @Override
    public SecretKey generateKey() throws NoSuchAlgorithmException {
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        return secretKey;
    }


    @Override
    public String encrypt(byte[] plainTextByte, Key secretKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        Base64.Encoder encoder = Base64.getEncoder();
        String encryptedText = encoder.encodeToString(encryptedByte);

        return encryptedText;
    }

    @Override
    public byte[] decrypt(String encryptedText, Key secretKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

        return decryptedByte;
    }

}
