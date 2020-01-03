package com.psl.cryptography.assignment;

import com.psl.cryptography.assignment.model.Party;
import com.psl.cryptography.assignment.service.cryptography.CryptoFactory;
import com.psl.cryptography.assignment.service.cryptography.Cryptography;
import com.psl.cryptography.assignment.service.packet.Packet;
import org.json.simple.JSONObject;

import java.security.*;

import static com.psl.cryptography.assignment.util.CryptoUtils.fakeLoading;

public class Main {
    public static void main(String a[]){
        //Controls the processing time of output for better console log readability
        int loadTime = 1000;

        //Generating RSA Key Pairs(public,private) for Sender
        KeyPair keyPair = null;
        Cryptography rsa = CryptoFactory.getCrypto("RSA");
        System.out.print("\nGenerating RSA Key Pairs(public,private) for Sender");
        try {
            keyPair = (KeyPair) rsa.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.print("\nSorry, couldn't generate RSA key pair due to "+e+". Please try again.");
        }
        fakeLoading(loadTime);
        Party sender = new Party();
        sender.setPrivateKey(keyPair.getPrivate());
        sender.setPublicKey(keyPair.getPublic());


        //Generating RSA Key Pairs(public,private) for Receiver
        System.out.print("\nGenerating RSA Key Pairs(public,private) for Receiver");
        try {
            keyPair = (KeyPair) rsa.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.print("\nSorry, couldn't generate RSA key pair due to "+e+". Please try again.");
        }
        fakeLoading(loadTime);
        Party receiver = new Party();
        receiver.setPrivateKey(keyPair.getPrivate());
        receiver.setPublicKey(keyPair.getPublic());


        //Exchanging Keys
        System.out.print("\nExchanging RSA Public Key between Sender and Receiver");
        sender.setOtherPartyPublicKey(receiver.getPublicKey());
        receiver.setOtherPartyPublicKey(sender.getPublicKey());
         fakeLoading(loadTime);

        //Creating JSON Object
        JSONObject json = new JSONObject();
        json.put("name", "Chinmoy");
        json.put("id", "025220");
        json.put("role", "Project Engineer");
        json.put("BU", "Corporate CTO Organization");

        sender.setMessage(json.toString());

        System.out.print("\nJSON to be encrypted: \n"+sender.getMessage());

      /*  Packing the message accordingly
         1. Sender hashes the JSON object and signs the hash
         2. Generate a AES256 symmetric key
         3. Sender packages the JSON object and its signature, and encrypts this with the symmetric key .
         4. Sender encrypts the symmetric key with the receiver's public key.*/
        String packet = Packet.createCryptoPacket(sender.getMessage(), sender.getPrivateKey(), sender.getOtherPartyPublicKey(),loadTime);

        sender.setEncryptedPacket(packet);
        receiver.setEncryptedPacket(packet);

        String extractedMessage = Packet.decryptCryptoPacket(receiver.getEncryptedPacket(), receiver.getPrivateKey(), receiver.getOtherPartyPublicKey(),loadTime);

        if (extractedMessage == null) {
            System.out.print("\nUnsuccessful in Extracting the Message from crypto-packet.");
        } else {
            System.out.println("\n\n --------------------------SUCCESS-------------------------");
            System.out.print("\nSuccessfully Extracted the Original Message from the crypto-packet\nThe JSON message:\n"+extractedMessage);
            receiver.setMessage(extractedMessage);
        }
    }
}
