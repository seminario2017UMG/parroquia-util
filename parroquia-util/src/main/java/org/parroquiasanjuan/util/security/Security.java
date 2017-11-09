package org.parroquiasanjuan.util.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author lveliz
 */
public class Security {

    private static final char[] CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890@#!=+-_*%".toCharArray();
    public static final int ITERATION_COUNT = 40000;
    public static final int KEY_LENGTH = 128;

    public static byte[] generatePasswordSalt() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[10];
        random.nextBytes(bytes);
        return bytes;
    }

    public static String generateTempPassword() {

        StringBuilder tempPassword = new StringBuilder();
        Random random = new Random();
        char c;

        for (int i = 0; i < 8; i++) {
            c = CHARS[random.nextInt(CHARS.length)];
            tempPassword.append(c);
        }

        return tempPassword.toString();

    }

    public static SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey keyTmp = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
    }

    public static String encrypt(String property, SecretKeySpec key) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters parameters = pbeCipher.getParameters();
        IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
        byte[] cryptoText = pbeCipher.doFinal(property.getBytes("UTF-8"));
        byte[] iv = ivParameterSpec.getIV();
        return base64Encode(iv) + ":" + base64Encode(cryptoText);
    }

    public static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static String decrypt(String string, SecretKeySpec key) throws GeneralSecurityException, IOException {
        String iv = string.split(":")[0];
        String property = string.split(":")[1];
        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
        return new String(pbeCipher.doFinal(base64Decode(property)), "UTF-8");
    }

    public static byte[] base64Decode(String property) throws IOException {
        return Base64.getDecoder().decode(property);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, GeneralSecurityException, IOException {
        
        String password = "W3M682%X";
        byte[] salt = base64Decode("KE5FfT21C80vUg==");
        String enc = "0XWFA9Jt41Y6vMq5xtszKQ==:XneAwu/lIdTQLWgyeFe4Fg==";

        SecretKeySpec key = createSecretKey(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        
        System.out.format("%10s | %15s | %50s | %10s \n", "PASSWORD", "SALT", "ENCRIPTED", "DECRIPTED");
        System.out.format("%10s | %15s | %50s | %10s", password, base64Encode(salt), enc, decrypt(enc, key));


    }

}
