package com.psl.cryptography.assignment.util;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Optional;

public class CryptoUtils {

    public static String pack(String... str) {
        String packet = "";
        for (String data : str) {
            packet += "."+data;
        }
        packet = packet.substring(1, packet.length());
        return packet;
    }

    public static String[] unpack(String str) {
        String[] unpackArr = str.split("\\.",2);
       //Arrays.stream(unpackArr).map(encodedString -> new String(Base64.getDecoder().decode(encodedString)));
        return unpackArr;
    }

    public static Key bytesToKey(byte[] encodedKey, String algoName){
        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, algoName);

        return originalKey;
    }

    public static void checkOptional(Optional entity){
        if(!entity.isPresent()){
            System.out.print("Sorry, Exiting due to unexpected null pointer exception...");
            System.exit(0);
        }
    }

    //Fake Loading to simulate real life loading
    //Parameters can be changed according to preference
    public static void fakeLoading(int loadTime){
        for(int i = 0; i < 5; i++) {
            try {
                Thread.sleep(loadTime);
                System.out.print(".");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        System.out.print("done");
    }

}
