package com.psl.cryptography.assignment.service.sign;


import com.psl.cryptography.assignment.service.sign.sha_rsa.SHA_RSA;

public class SignFactory {

    public static Sign getHashSign(String str){
        if("SHA_RSA".equalsIgnoreCase(str)) {
            return new SHA_RSA();
        }

        return null;
    }

}
