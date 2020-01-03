package com.psl.cryptography.assignment.service.packet;

import com.psl.cryptography.assignment.service.cryptography.CryptoFactory;
import com.psl.cryptography.assignment.service.cryptography.Cryptography;
import com.psl.cryptography.assignment.service.sign.Sign;
import com.psl.cryptography.assignment.service.sign.SignFactory;
import com.psl.cryptography.assignment.util.CryptoUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Optional;

import static com.psl.cryptography.assignment.util.CryptoUtils.checkOptional;
import static com.psl.cryptography.assignment.util.CryptoUtils.fakeLoading;

public class Packet {
    public static String createCryptoPacket(String message, PrivateKey senderPrivateKey, PublicKey receiverPublicKey, int loadTime){
        System.out.print("\n __________________________________________________________\n'                                                          '\n|         Orchestrating Sender Side Behaviour              |\n'----------------------------------------------------------'");

        Cryptography rsa = CryptoFactory.getCrypto("RSA");

        //Hashing and Signing the JSON
        System.out.print("\nHashing(SHA256) and Signing(RSA) the JSON with senders private key");
        Optional<String> digitalSign = Optional.empty();
        Sign sha_rsa = SignFactory.getHashSign("SHA_RSA");
        try {
            digitalSign = Optional.ofNullable(sha_rsa.sign(message, senderPrivateKey));
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        checkOptional(digitalSign);
        fakeLoading(loadTime);


        //Packing the JSON data and Digital Signature into a single Packet
        //Base64 encode the JSON and Digital Signature
        System.out.print("\nPacking the JSON data and Digital Signature into a single Packet");
        String packet = CryptoUtils.pack(message,digitalSign.get());
        fakeLoading(loadTime);


        //Generating AES key
        Cryptography aes = CryptoFactory.getCrypto("AES");
        Optional<SecretKey> aesSecretKey = Optional.empty();
        System.out.print("\nGenerating AES Key");
        try {
            aesSecretKey = Optional.ofNullable((SecretKey) aes.generateKey());
        } catch (NoSuchAlgorithmException e) {
            System.out.print("\nSorry, couldn't generate AES key due to "+e+". Please try again");
        }
        checkOptional(aesSecretKey);
        fakeLoading(loadTime);


        //Encrypting the packet with AES Secret Key
        System.out.print("\nEncrypting the packet with AES Secret Key");
        Optional<String> aesEncryptedPacket = Optional.empty();
        try {
            aesEncryptedPacket = Optional.ofNullable(aes.encrypt(packet.getBytes(), aesSecretKey.get()));
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            System.out.print("\nSorry, couldn't Encrypt the packet with AES Secret Key due to "+e+". Please try again");
        }
        checkOptional(aesEncryptedPacket);
        fakeLoading(loadTime);


        //Encrypting the AES Secret Key with Receiver's Public RSA Key
        System.out.print("\nEncrypting the AES Secret Key with Receiver's Public RSA Key");
        Optional<String> rsaEncryptedAESKey = Optional.empty();
        try {
            rsaEncryptedAESKey = Optional.ofNullable(rsa.encrypt(aesSecretKey.get().getEncoded(), receiverPublicKey));
        } catch (BadPaddingException|IllegalBlockSizeException|InvalidKeyException e) {
            System.out.print("\nSorry, couldn't Encrypt the AES Secret Key with Receiver's Public RSA Key due to "+e+". Please try again");
        }
        checkOptional(rsaEncryptedAESKey);
        fakeLoading(loadTime);


        //Creating the Final packet consisting AES256 encrypted packet and RSA encrypted AES Key
        System.out.print("\nCreating the Final packet consisting AES256 encrypted packet and RSA encrypted AES Key");
        String finalPacket = CryptoUtils.pack(aesEncryptedPacket.get(),rsaEncryptedAESKey.get());
        fakeLoading(loadTime);

        return finalPacket;
    }

    public static String decryptCryptoPacket(String encryptedPacket, PrivateKey privateKey, PublicKey otherPartyPublicKey, int loadTime) {
        System.out.print("\n __________________________________________________________\n'                                                          '\n|        Orchestrating Receiver Side Behaviour             |\n'----------------------------------------------------------'");
        Cryptography rsa = CryptoFactory.getCrypto("RSA");
        Cryptography aes = CryptoFactory.getCrypto("AES");

        System.out.print("\nUnpacking the packet to get sub-packet and RSA encrypted AES256 Key");
        String[] unpackedArr = CryptoUtils.unpack(encryptedPacket);
        String messageBodyAndSign = unpackedArr[0];
        String encryptedAESKey = unpackedArr[1];
         fakeLoading(loadTime);

        //Decrypting the AES key with Receivers RSA Private Key
        System.out.print("\nDecrypting the AES256 key with Receivers RSA Private Key");

        Optional<byte[]> decryptedAESKey = Optional.empty();;
        try {
            decryptedAESKey = Optional.ofNullable(rsa.decrypt(encryptedAESKey, privateKey));
        } catch (BadPaddingException|IllegalBlockSizeException|InvalidKeyException e) {
            System.out.print("\nSorry, couldn't Decrypt the AES Secret Key with Receiver's Private RSA Key due to "+e+". Please try again");
        }
        checkOptional(decryptedAESKey);
         fakeLoading(loadTime);


        //Use the AES Key to decrypt the message body
        System.out.print("\nDecrypting the Message Body using the decrypted AES key");
        Optional<byte[]> aesDecryptedPacket = Optional.empty();;
        SecretKey originalKey = (SecretKey) CryptoUtils.bytesToKey( decryptedAESKey.get(),"AES");
        try {
            aesDecryptedPacket = Optional.ofNullable(aes.decrypt(messageBodyAndSign, originalKey));
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            System.out.print("\nSorry, couldn't Decrypt the packet with AES Secret Key due to "+e+". Please try again");
        }
        checkOptional(aesDecryptedPacket);
         fakeLoading(loadTime);


        //Extracting the Original Message and Digital Signature from the packet
        System.out.print("\nUnpacking the packet to get the Original Message and Digital Signature");
        String decryptedStrPacketArr[] = CryptoUtils.unpack((new String(aesDecryptedPacket.get())));
        String originalMessage = decryptedStrPacketArr[0];
        String digitalSignature = decryptedStrPacketArr[1];
         fakeLoading(loadTime);

        //Verify the digital signature
        System.out.print("\nVerifying the Packets Digital Signature for checking Integrity");
        boolean verified = false;
        Sign sha_rsa = SignFactory.getHashSign("SHA_RSA");

        try {
            verified = sha_rsa.verify(originalMessage.getBytes(),digitalSignature.getBytes(),otherPartyPublicKey);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            System.out.print("\nSorry, couldn't Verify Senders Public Key due to "+e+". Please try again");
        }
         fakeLoading(loadTime);
        if(!verified) {
            System.out.print("\nIntegrity of the crypto-packet received can't be verified as the Digital Signature doesn't match the payload");
        }

        return verified ? originalMessage : null;
    }
}
