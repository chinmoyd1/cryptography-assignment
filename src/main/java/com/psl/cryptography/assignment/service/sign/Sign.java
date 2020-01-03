package com.psl.cryptography.assignment.service.sign;

import java.security.*;

public interface Sign {

    public String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException;
    public Boolean verify(byte[] message, byte[] digitalSign, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException;
}
