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
import static faith.elguadia.tadpool.tad.tadModification.*;

public class start {
    public static void main(String[] args) {
        int c = 0;
        if (args.length >= 2) {
            if (args[1].equals("d")) {

                File f = new File(args[0]);
                System.out.println(f.getName());
                File f2 = new File(Constants.default_dir);
                if (!f2.exists()) {
                    if(!f2.mkdir()){
                        System.out.println("mkdir failed. please check disk space or permission.");
                        System.exit(1);
                    }
                }
                if (!f.exists()) System.exit(1);
                try {
                    getDump(f, 0x0, 0x4000, "banner.bin");
                    getDump(f, 0x4020, 0xF0, "header.bin");
                    getDump(f, 0x4130, 0x4E0, "footer.bin");
                    getContentSize(new File(Constants.default_dir + "header.bin")); // Now constant array is set
                    int off = TMD;
                    for (int i : content_sizelist) {
                        if (i != 0) {
                            getDump(f, off, i, content_list[c]);
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
                    signFooter(new File("ctcert.bin"),new File(default_dir+"footer.bin"));
                    rebuildTad(args[0]);
                } catch (Exception e) {
                    e.printStackTrace();
                    // Empty.
                }
            }
        } else {
            System.out.println("TADpole-Java By Chromaryu: https://github.com/knight-ryu12");
            System.out.println("in support of jason0594, saibotu, Kartik");
            System.out.println("Usage: java -jar TADpole.jar <DSiware export.bin> <r/d>");
            System.out.println("r = rebuild, d = dump");
            System.exit(0);

        }
    }
}
