package faith.elguadia.tadpool;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class api {
    public static BigInteger add_128(BigInteger a,BigInteger b){
        BigInteger f128 = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",16);
        return a.add(b).and(f128);
    }
    public static BigInteger rol_128(BigInteger n, int shift) {
        BigInteger f128 = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",16);
        BigInteger left = n.shiftLeft(shift % 128);
        BigInteger right = n.shiftRight(128 - (shift % 128));
        return left.or(right).and(f128);
    }
    public static byte[] getNormalKey(BigInteger x,BigInteger y) {
        BigInteger n = rol_128(x,2);
        System.out.println(n);
        n = n.xor(y);
        System.out.println(n);
        n = add_128(n,new BigInteger("1FF9E9AAC5FE0408024591DC5D52768A",16));
        System.out.println(n);
        n = rol_128(n,87);
        System.out.println(n);
        return n.toByteArray();
    }

    public static byte[] decryptMessage(String s,byte[] key,byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        final SecretKey sk = new SecretKeySpec(key,"AES");
        cipher.init(Cipher.DECRYPT_MODE,sk,new IvParameterSpec(iv));
        return cipher.update(s.getBytes());
    }
}
