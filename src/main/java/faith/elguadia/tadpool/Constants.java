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
        try {
            keyx =      Hex.decodeHex("6FBB01F872CAF9C01834EEC04065EE53");
            keyx_bigint=new BigInteger("6FBB01F872CAF9C01834EEC04065EE53",16);
            C =         Hex.decodeHex("1FF9E9AAC5FE0408024591DC5D52768A");

            cmac_keyx = Hex.decodeHex("B529221CDDB5DB5A1BF26EFF2041E875");
        } catch (DecoderException e) {
            e.printStackTrace();
        }
        byte[] keyY = new byte[16];
        File f = new File("movable.sed");

        try(FileInputStream fis = new FileInputStream(f); BufferedInputStream bis = IOUtils.buffer(fis)) {
            bis.skip(0x110);
            bis.read(keyY,0,0x10);
        } catch (IOException e) {
            e.printStackTrace();
        }
        keyy=keyY;
        System.out.println(Hex.encodeHexString(keyY));
        keyy_bigint=new BigInteger(Hex.encodeHexString(keyY),16);
    }
    public static byte[] keyx;
    public static BigInteger keyx_bigint;
    public static byte[] keyy; //movable.sed.
    public static BigInteger keyy_bigint;
    //public static byte[] F128;
    public static byte[] C;
    //public static BigInteger C_bigint;
    public static byte[] cmac_keyx;
    public static String default_dir = "decrypted_sections/";
    public static int BM = 0x20;
    public static int banner = 0x0;
    public static int banner_size = 0x4000;
    public static int header = banner + banner_size + BM;
    public static int header_size = 0xF0;
    public static int footer = header + header_size + BM;
    public static int footer_size = 0x4E0;
    public static int TMD = footer + footer_size + BM;
    public static int TMD_SIZE = 0xB40;
    public static int SRL = TMD + TMD_SIZE + BM;
    public static int SRL_SIZE = 0x0; // Need INIT THIS PLEASE
    public static int SAV = 0x0;
    public static int SAV_SIZE = 0x0;

    public static String[] content_list = {"tmd","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav"};
    public static int content_sizelist = content_list.length;

}
