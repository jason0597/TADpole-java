package faith.elguadia.tadpool.tad;

import org.apache.commons.codec.binary.Hex;

import org.bouncycastle.asn1.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;

public class ctCertHandling {
    //
    public static KeyPair getKeyPair(byte[] ctcert) {
        //Prepare tmpByte[]
        byte[] bkey = Arrays.copyOfRange(ctcert,0x180, 0x19E);
        byte[] br = Arrays.copyOfRange(ctcert,0x108, 294);
        byte[] bs = Arrays.copyOfRange(ctcert, 294, 324);
        // --
        KeyFactory kf = null;
        ECParameterSpec ep;
        KeyPair kp = null;
        // DebugOut
        System.out.printf("PrivKey - %s\n",Hex.encodeHexString(bkey));
        System.out.printf("R - %s\n",Hex.encodeHexString(br));
        System.out.printf("S - %s\n",Hex.encodeHexString(bs));
        BigInteger r,s;
        BigInteger key;
        r = new BigInteger(br);
        s = new BigInteger(bs);
        key = new BigInteger(bkey);
        System.out.println("Key set.");

        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ECGenParameterSpec sp = new ECGenParameterSpec("sect233r1");
            ap.init(sp);
            System.out.println("ap - "+ap.getAlgorithm());
            ep = ap.getParameterSpec(ECParameterSpec.class);
            kf = KeyFactory.getInstance("EC");
            kp = new KeyPair(
                    kf.generatePublic(new ECPublicKeySpec(new ECPoint(r,s),ep)),
                    kf.generatePrivate(new ECPrivateKeySpec(key,ep))
            );
            System.out.println("Key Generated " + kp.getPublic() +":" + kp.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return kp;
    }

    public static void sign(KeyPair kp,byte[] ctcert,byte[] footer) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // StartInit
        final int totalhashsize = 13 * 0x20;
        //byte[] tmpfooter = footer;
        //byte[] tmpctcert = ctcert;
        // EndInit
        // Prepare Sys
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(kp.getPrivate());
        System.out.println("Sig:"+sig.toString());
        // CTcert -> footer
        System.out.printf("Step1: CTCert to Footer...");
        System.arraycopy(ctcert,0,footer,totalhashsize+0x1BC,0x180);
        System.out.printf("Done\n");
        // Copy pubkey from ctcert -> APCert
        System.out.printf("Step2: PubKey to APCert...");
        System.arraycopy(ctcert,0x108,footer,totalhashsize+0x3C+0x108,0x3C);
        System.out.printf("Done\n");
        // Sign hash at the top.
        System.out.printf("Step3: Signing Hash...\n");
        sig.update(getHash(footer));
        byte[] hashSig = sig.sign();
        System.out.printf("hashSig of footer hashes -> %s\n",Hex.encodeHexString(hashSig));
        byte[] sigRS = parseSig(hashSig);
        System.out.printf("R and S of Signature -> %s\n",Hex.encodeHexString(sigRS));
        System.arraycopy(sigRS,0,footer,totalhashsize,0x3C);
        System.out.printf("Done\n");

        // get String issuer
        System.out.printf("Step4: Adding issuer...");
        byte[] keyid = getKeyID(footer);
        System.arraycopy(keyid,0,footer,totalhashsize+0x3c+0x80,0x40);
        System.out.printf("Done\n");
        //Sign the APCert in the offset of 0x80-0x180 (0x100 bytes in total)
        System.out.printf("Step5: Getting APCSign...\n");
        byte[] APCSign = new byte[0x100];
        System.arraycopy(footer,totalhashsize+0x3C+0x80,APCSign,0,APCSign.length);
        System.out.printf("hashSig of footer hashes -> %s\n",Hex.encodeHexString(APCSign));
        //Here we sign the bytes, and then place them in the correct spot where the signature goes for the APCert
        sig.update(APCSign);
        byte[] apcert_signature = sig.sign();
        System.out.printf("Signature of APCSign -> %s\n",Hex.encodeHexString(apcert_signature));
        byte[] apcert_signature_R_S = parseSig(apcert_signature);
        System.out.printf("R and S of APCSign -> %s\n",Hex.encodeHexString(apcert_signature_R_S));
        System.arraycopy(apcert_signature_R_S, 0, footer, totalhashsize + 0x3C + 4, 0x3C);
        System.out.printf("Done\n");
        // End
    }

    private static byte[] getKeyID(byte[] footer) {
        final int totalhashsize = 13 * 0x20;
        byte[] issuer = new byte[0x40];
        System.arraycopy(footer, totalhashsize + 0x1BC + 0x80, issuer, 0, 33);
        String issuer_str = new String(issuer, 0, 33);

        byte[] keyid = new byte[0x40];
        System.arraycopy(footer, totalhashsize + 0x1BC + 0x80 + 0x40 + 4, keyid, 0, 0x40);
        int i; for (i = 0; i < keyid.length && keyid[i] != 0; i++) { ; }
        String keyid_str = new String(keyid, 0, i);

        String str = issuer_str + "-" + keyid_str;
        byte[] str_bytes = str.getBytes();
        byte[] returnvalue = new byte[0x40];
        System.arraycopy(str_bytes, 0, returnvalue, 0, str_bytes.length);

        return returnvalue;
    }

    private static byte[] getHash(byte[] footer) {
        return Arrays.copyOfRange(footer,0,13*0x20);
    }

    public static byte[] parseSig(byte[] sig) {
        ArrayList<BigInteger> signature_R_S = new ArrayList<>();
        try (ByteArrayInputStream bais = new ByteArrayInputStream(sig); ASN1InputStream asn1is = new ASN1InputStream(bais)) {
            ASN1Primitive asn1 = asn1is.readObject();
            if(asn1 instanceof ASN1Sequence) {
                ASN1Sequence asn1s = (ASN1Sequence) asn1;
                ASN1Encodable[] asn1eArray = asn1s.toArray();
                for(ASN1Encodable asn1e : asn1eArray) {
                    ASN1Primitive asn1Primitive = asn1e.toASN1Primitive();
                    if (asn1Primitive instanceof ASN1Integer) {
                        ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
                        signature_R_S.add(asn1Integer.getValue());
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] return_value = new byte[2 * 0x1E];
        byte[] R = signature_R_S.get(0).toByteArray();
        byte[] S = signature_R_S.get(1).toByteArray();
        System.arraycopy(R, 0, return_value, 0x1E - R.length, R.length);
        System.arraycopy(S, 0, return_value, 0x1E + (0x1E - S.length), S.length);
        return return_value;

    }

}
