package com.psl.cryptography.assignment.service.cryptography;

import com.psl.cryptography.assignment.service.cryptography.asymmetric.RSA;
import com.psl.cryptography.assignment.service.cryptography.symmetric.AES;

public class CryptoFactory {

    public static Cryptography getCrypto(String str){
        if("RSA".equalsIgnoreCase(str)) {
            return new RSA();
        }
        else if("AES".equalsIgnoreCase(str)){
            return new AES();
        }

        return null;
    }

}
