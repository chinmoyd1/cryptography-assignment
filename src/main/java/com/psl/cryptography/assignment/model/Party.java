package com.psl.cryptography.assignment.model;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Party {

   private PublicKey publicKey;
   private PrivateKey privateKey;
   private PublicKey otherPartyPublicKey;
   private String message;
   private String encryptedPacket;

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getOtherPartyPublicKey() {
        return otherPartyPublicKey;
    }

    public void setOtherPartyPublicKey(PublicKey otherPartyPublicKey) {
        this.otherPartyPublicKey = otherPartyPublicKey;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getEncryptedPacket() {
        return encryptedPacket;
    }

    public void setEncryptedPacket(String encryptedPacket) {
        this.encryptedPacket = encryptedPacket;
    }
}
