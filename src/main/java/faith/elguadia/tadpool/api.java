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

import static faith.elguadia.tadpool.Constants.*;

public class api {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static BigInteger add_128(BigInteger a, BigInteger b){
        return a.add(b).and(F128);
    }
    private static BigInteger rol_128(BigInteger n, int shift) {
        BigInteger left = n.shiftLeft(shift % 128);
        BigInteger right = n.shiftRight(128 - (shift % 128));
        return left.or(right).and(F128);
    }
    public static byte[] getNormalKey(BigInteger x,BigInteger y) {
        BigInteger n = rol_128(x,2);
        n = n.xor(y);
        n = add_128(n,C);
        n = rol_128(n,87);
        byte[] array = n.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array;
    }

    public static byte[] decryptMessage(byte[] s,byte[] key,byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        final SecretKey sk = new SecretKeySpec(key,"AES");
        cipher.init(Cipher.DECRYPT_MODE,sk,new IvParameterSpec(iv));
        return cipher.update(s);
    }

    public static byte[] encryptMessage(byte[] s,byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        final SecretKey sk = new SecretKeySpec(key,"AES");
        cipher.init(Cipher.ENCRYPT_MODE,sk,new IvParameterSpec(iv));
        return cipher.update(s);
    }




}
