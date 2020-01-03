package com.psl.cryptography.assignment.util;

import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class CryptoUtilsTest {
    static SecretKey secretKey;

    @BeforeClass
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");;
        keyGenerator.init(256);
        secretKey = keyGenerator.generateKey();
    }

    @Test
    public void pack() {
        String str1 = "String1";
        String str2 ="String2";
        String expectedString = str1+"."+str2;

        String packedString = CryptoUtils.pack(str1,str2);

        assertEquals(expectedString,packedString);
    }

    @Test
    public void unpack() {
        String packedStr = "String1.String2";
        String str1 = "String1";
        String str2 ="String2";

        String[] unpacked = CryptoUtils.unpack(packedStr);
        assertEquals(str1, unpacked[0]);
        assertEquals(str2, unpacked[1]);
    }

    @Test
    public void bytesToKey() {
        SecretKey sk = (SecretKey) CryptoUtils.bytesToKey(secretKey.getEncoded(),"AES");
        assertEquals(secretKey,sk);
    }

}