package faith.elguadia.tadpool;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.*;
import java.util.*;

import static faith.elguadia.tadpool.Constants.*;

public class start {
    public static void main(String[] args) {
        int c = 0;
        if (args.length >= 2) {
            if (args[1].equals("d")) {

                File f = new File(args[0]);
                System.out.println(f.getName());
                File f2 = new File(Constants.default_dir);
                if (!f2.exists()) f2.mkdir();
                if (!f.exists()) System.exit(1);
                try {
                    getDump(f, 0x0, 0x4000, "banner.bin");
                    getDump(f, 0x4020, 0xF0, "header.bin");
                    getDump(f, 0x4130, 0x4E0, "footer.bin");
                    getContentSize(new File(Constants.default_dir + "header.bin")); // Now constant array is set
                    int off = TMD;
                    for (long i : content_sizelist) {
                        if (i != 0) {
                            getDump(f, off, (int) i, content_list[c]);
                            off += (i + BM);
                        }
                        c++;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (args[1].equals("r")) {
                try {
                    fixHash(new File(default_dir + "header.bin"), new File(default_dir + "footer.bin"));
                    signFooter();
                    rebuildTad(args[0]);
                } catch (Exception e) {
                    e.printStackTrace();
                    // Empty.
                }
            }
        }
    }

    private static void rebuildTad(String id) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        List<String> full_namelist = new ArrayList<>();
        full_namelist.add("banner.bin");
        full_namelist.add("header.bin");
        full_namelist.add("footer.bin");
        Collections.addAll(full_namelist, content_list);
        File target = new File(id+".patched");
        byte[] key = api.getNormalKey(keyx,keyy);
        byte[] bm;
        byte[] content;
        byte[] section;
        byte[] iv = new byte[0x10];
        //tad_section = new ArrayList<>(14);
        File f;
        try(FileOutputStream fos = new FileOutputStream(target)) {
            for (String s : full_namelist) {
                f = new File(default_dir + s);
                if (f.exists()) {
                    System.out.println("Encrypting:" + s);
                    content = Files.readAllBytes(f.toPath());
                    bm = generateBlockMetadata(content); // 0x0+10 = AES MAC over SHA256(SHA256 of PlainData), 0x10+10 = IV (RandGen)
                    System.arraycopy(bm, 0x10, iv, 0, iv.length); // bm -> IV
                    System.out.println("L92IV:"+Hex.encodeHexString(iv)); // is IV Okay?
                    content = api.encryptMessage(content, key, iv); // Encrypt.
                    System.out.println("Length:"+content.length); // contentLength
                    section = new byte[content.length + bm.length]; // section is content+bm
                    System.out.println("New Length:"+section.length);
                    if(section.length == content.length+0x20){ // checing.
                        System.arraycopy(content, 0, section, 0, content.length); // Merge1
                        System.arraycopy(bm, 0, section, content.length, bm.length); // Merge2
                        fos.write(section);
                    }
                }
            }
            fos.flush();
        }
        //System.out.println(tad_section);
    }


    private static void signFooter() throws IOException {
        //Process p = Runtime.getRuntime().exec("ctr-dsiwaretool.exe "+default_dir+footerName+" ctcert.bin --write");
        ProcessBuilder pb = new ProcessBuilder("ctr-dsiwaretool.exe",""+default_dir+ "footer.bin","ctcert.bin","--write")
                .inheritIO()
                .directory(new File(System.getProperty("user.dir")));

        pb.start();
        //System.out.println(p.getInputStream().read());
    }

    private static byte[] generateBlockMetadata(byte[] content) throws NoSuchAlgorithmException { //Get ContentBlock
        System.out.println("Entry generateBM.");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] ret = new byte[0x20];
        byte[] hash = md.digest(content);
        System.out.println("Hash:"+Hex.encodeHexString(hash));
        byte[] key = api.getNormalKey(cmac_keyx,keyy);
        System.out.println("CMACKey:"+Hex.encodeHexString(key));
        // Generating CMAC here.
        CipherParameters cp = new KeyParameter(key);
        //BlockCipher aes = new AESEngine();
        CMac mac = new CMac(new AESEngine(),128);
        mac.init(cp);
        mac.update(hash,0,hash.length);
        mac.doFinal(ret,0);
        System.out.println(Hex.encodeHexString(ret));
        //Generate IV here
        byte[] iv = new byte[0x10];
        sr.nextBytes(iv);
        System.arraycopy(iv, 0, ret, 0x10, iv.length);
        System.out.println("IV:"+Hex.encodeHexString(iv));
        System.out.println("Ret:"+Hex.encodeHexString(ret));
        return ret;

    }


    private static void fixHash(File header, File footer) throws NoSuchAlgorithmException, IOException, DecoderException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        File tmp;
        int i = 0;
        int[] sizes = new int[11];
        String[] hash = new String[13];
        List<String> footer_namelist = new ArrayList<>();
        footer_namelist.add("banner.bin");
        footer_namelist.add("header.bin");
        Collections.addAll(footer_namelist, content_list);
        for (String s : content_list) {
            tmp = new File(default_dir + s);
            sizes[i] = tmp.exists() ? (int) tmp.length() : 0;
            if (tmp.length() == 0xB40) sizes[i] = 0xB34;
            i++;
        }
        //sizes[0] = 0xB34;

        System.out.println(Arrays.toString(sizes)); // Debug
        i = 0; // Reset Counter.
        for (String s : footer_namelist) {
            tmp = new File(default_dir + s);
            hash[i] = tmp.exists() ? Hex.encodeHexString(md.digest(Files.readAllBytes(tmp.toPath()))) : "0000000000000000000000000000000000000000000000000000000000000000";
            i++;
        }
        System.out.println(Arrays.toString(hash));

        //System.out.println(sizes);
        try(RandomAccessFile raf = new RandomAccessFile(header,"rwd")) {
            ByteBuffer buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            int off = 0x48;
            for(int sz : sizes) {
                buf.putInt(sz);
                buf.rewind();
                raf.seek(off);
                raf.write(buf.array());
                off+=4;
            }
        }
        System.out.println("Header fixed.");
        try(RandomAccessFile raf = new RandomAccessFile(footer,"rwd")) {
            int off = 0;
            for(String s : hash) {
                raf.seek(off);
                raf.write(Hex.decodeHex(s));
                off+=0x20;
            }
        }
        System.out.println("Footer fixed.");
    }

    private static void getDump(File f,int data_offset,int size,String filename) throws IOException,NoSuchAlgorithmException,NoSuchPaddingException,InvalidAlgorithmParameterException,InvalidKeyException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        System.out.println("Dumping:"+filename);
        byte[] key = api.getNormalKey(keyx, keyy);
        System.out.println("Using NK:"+Hex.encodeHexString(key));
        byte[] iv = new byte[16];
        byte[] enc = new byte[size];
        byte[] dec;
        try(FileInputStream fis = new FileInputStream(f); BufferedInputStream bis = new BufferedInputStream(fis)) {
            bis.skip(data_offset);
            bis.read(enc,0,size); // Data skipped data_offset+size.
            bis.skip(0x10); // We don't need BM 0x0-0x10. = AES MAC
            bis.read(iv,0,0x10); // Read BM 0x10-0x20. = 16Byte IV!
        }
        System.out.println("Using IV:"+Hex.encodeHexString(iv));
        dec = api.decryptMessage(enc,key,iv);
        System.out.println("SHA-256:"+Hex.encodeHexString(md.digest(dec)));
        File out = new File(Constants.default_dir+filename);
        System.out.println("Writing to file:"+filename);
        try(FileOutputStream fos = new FileOutputStream(out)) {
            IOUtils.write(dec, fos);
        }
    }

    private static void getContentSize(File header){
        try {
            byte[] h = Files.readAllBytes(header.toPath());
            System.out.println(h.length);
            ByteBuffer buffer = ByteBuffer.allocate(0x2C).order(ByteOrder.LITTLE_ENDIAN).put(h, 0x48, 0x2C);
            buffer.rewind();
            for(int i =0; i<11; i++) {
                long c = Integer.toUnsignedLong(buffer.getInt());
                if(c == 0xB34) {
                    c = 0xB40; //Dirtyhaxx
                }
                content_sizelist[i] = c;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(Arrays.toString(content_sizelist));
    }
}
