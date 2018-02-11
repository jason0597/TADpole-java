package faith.elguadia.tadpool;

import org.apache.commons.codec.binary.Hex;

import java.util.Arrays;

public class start {
    public static void main(String[] args) {
        //System.out.println(Hex.encodeHexString(Constants.keyx));
        //long i = Long.parseLong(
        //        "148515307011192255396052804737821961811");
        //System.out.println(Hex.encodeHexString(Constants.keyy));
        System.out.println(Hex.encodeHexString(api.getNormalKey(Constants.keyx_bigint,Constants.keyy_bigint)));
    }
}
