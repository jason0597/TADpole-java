package faith.elguadia.tadpool;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Constants {
    static {
        keyx = new BigInteger("6FBB01F872CAF9C01834EEC04065EE53", 16);
        F128 = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        C = new BigInteger("1FF9E9AAC5FE0408024591DC5D52768A", 16);
        cmac_keyx = new BigInteger("B529221CDDB5DB5A1BF26EFF2041E875", 16);
        byte[] keyY = new byte[16];
        File f = new File("movable.sed");

        try (FileInputStream fis = new FileInputStream(f); BufferedInputStream bis = IOUtils.buffer(fis)) {
            bis.skip(0x110);
            bis.read(keyY, 0, 0x10);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(Hex.encodeHexString(keyY));
        keyy = new BigInteger(Hex.encodeHexString(keyY), 16);
    }

    public static BigInteger keyx;
    public static BigInteger keyy; //movable.sed.
    public static BigInteger F128;
    public static BigInteger C;
    //public static BigInteger C_bigint;
    public static BigInteger cmac_keyx;
    public static String default_dir = "decrypted_sections/";
    static int BM = 0x20;
    private static int banner = 0x0;
    private static int banner_size = 0x4000;
    private static int header = banner + banner_size + BM;
    private static int header_size = 0xF0;
    private static int footer = header + header_size + BM;
    private static int footer_size = 0x4E0;
    static int TMD = footer + footer_size + BM;
    private static int TMD_SIZE = 0xB40;
    public static int SRL = TMD + TMD_SIZE + BM;
    public static int SRL_SIZE = 0x0; // Need INIT THIS PLEASE
    public static int SAV = 0x0;
    public static int SAV_SIZE = 0x0;

    public static String[] content_list = {"tmd", "srl.nds", "2.bin", "3.bin", "4.bin", "5.bin", "6.bin", "7.bin", "8.bin", "public.sav", "banner.sav"};
    public static long[] content_sizelist = new long[content_list.length];

}
