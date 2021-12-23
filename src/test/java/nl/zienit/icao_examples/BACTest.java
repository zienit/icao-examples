package nl.zienit.icao_examples;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.Matchers;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertThat;

/**
 * Unit tests demonstrating:
 * ICAO
 * Doc 9303
 * Machine Readable Travel Documents
 * Seventh Edition, 2015
 * Part 11: Security Mechanisms for MRTDs
 * WORKED EXAMPLE: BASIC ACCESS CONTROL (INFORMATIVE)
 * <p>
 * The tests focus on the cryptography and on the construction of command- and responseData.
 * The enveloping APDUs are ignored because of their trivial nature.
 * <p>
 */
public class BACTest {

    // ICAO 9303 Part 11, section 9.7.1 Key Derivation Function
    // KDF(K,c) hardwired for cipher = 3DES, as applicable to BAC
    private byte[] KDF(byte[] K, byte[] c) {

        final var sha1 = new SHA1Digest();
        sha1.update(K, 0, K.length);
        sha1.update(c, 0, 4);
        final var digest = new byte[sha1.getDigestSize()];
        sha1.doFinal(digest, 0);
        // Note: adjusting the parity bits is optional (these bits are not used in 3DES; the parity bits are
        // all set to odd to help detect corruption of the key).
        final var keyDataA = Arrays.copyOf(digest, 8);
        final var keyDataB = Arrays.copyOfRange(digest, 8, 16);
        DESParameters.setOddParity(keyDataA);
        DESParameters.setOddParity(keyDataB);
        final var out = Arrays.copyOf(keyDataA, 16);
        System.arraycopy(keyDataB, 0, out, 8, 8);
        return out;
    }

    @Test
    public void testDeriveDocumentBasicAccessKeys() {

        // note: check digits are included
        final var documentNumber = "L898902C<3";
        final var dateOfBirth = "6908061";
        final var dateOfExpiry = "9406236";

        final var mrzInfo = (documentNumber + dateOfBirth + dateOfExpiry).getBytes();

        final var sha1 = new SHA1Digest();
        sha1.update(mrzInfo, 0, mrzInfo.length);
        final var out = new byte[sha1.getDigestSize()];
        sha1.doFinal(out, 0);

        final var Kseed = Arrays.copyOf(out, 16);
        assertThat(Kseed, Matchers.equalTo(Hex.decode("239AB9CB282DAF66231DC5A4DF6BFBAE")));

        final var Kenc = KDF(Kseed, new byte[]{0x00, 0x00, 0x00, 0x01});
        assertThat(Kenc, Matchers.equalTo(Hex.decode("AB94FDECF2674FDFB9B391F85D7F76F2")));

        final var Kmac = KDF(Kseed, new byte[]{0x00, 0x00, 0x00, 0x02});
        assertThat(Kmac, Matchers.equalTo(Hex.decode("7962D9ECE03D1ACD4C76089DCE131543")));
    }
}
