import faith.elguadia.tadpool.Constants;
import faith.elguadia.tadpool.api;
import faith.elguadia.tadpool.tad.tadModification;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class CMACTest {
    private final byte[] NormalKey = api.getNormalKey(Constants.cmac_keyx,new BigInteger("544144506f6c652d4a61766121202020",16));
    private final byte[] targetNormalKey = Hex.decodeHex("bcfebcfc40506fdae6efdc862693f72f");
    private final byte[] targetCMAC = Hex.decodeHex("b699e50d453122448492b2746a643ccf");
    public CMACTest() throws DecoderException {
    }

    @Test
    public void testAESCMAC() {
        assertArrayEquals(targetNormalKey,NormalKey);
        assertArrayEquals(targetCMAC,tadModification.getAESCMAC("This is easterEgg, No?".getBytes(),NormalKey));
    }

}
