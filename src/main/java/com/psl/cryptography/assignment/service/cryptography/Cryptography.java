package com.psl.cryptography.assignment.service.cryptography;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public interface Cryptography <E>{

    public E generateKey() throws NoSuchAlgorithmException;

    public String encrypt(byte[] plainTextByte, Key secretKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException;

    public byte[] decrypt(String encryptedText, Key secretKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException;
}
