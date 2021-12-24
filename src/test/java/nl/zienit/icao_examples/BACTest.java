package nl.zienit.icao_examples;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.util.Arrays;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.equalTo;
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
        assertThat(Kseed, equalTo(Hex.decode("239AB9CB282DAF66231DC5A4DF6BFBAE")));

        final var Kenc = KDF(Kseed, new byte[]{0x00, 0x00, 0x00, 0x01});
        assertThat(Kenc, equalTo(Hex.decode("AB94FDECF2674FDFB9B391F85D7F76F2")));

        final var Kmac = KDF(Kseed, new byte[]{0x00, 0x00, 0x00, 0x02});
        assertThat(Kmac, equalTo(Hex.decode("7962D9ECE03D1ACD4C76089DCE131543")));
    }

    // ICAO 9303 Part 11, section 4.3.3.1 Encryption of Challenge and Response
    private byte[] E(byte[] key, byte[] plaintext) throws InvalidCipherTextException {
        final var cipher = new BufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
        cipher.init(true, new DESedeParameters(key));
        final var ciphertext = new byte[plaintext.length];
        cipher.doFinal(ciphertext, cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0));
        return ciphertext;
    }

    private byte[] D(byte[] key, byte[] ciphertext) throws InvalidCipherTextException {
        final var cipher = new BufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
        cipher.init(false, new DESedeParameters(key));
        final var plaintext = new byte[ciphertext.length];
        cipher.doFinal(ciphertext, cipher.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0));
        return plaintext;
    }

    // ICAO 9303 Part 11, section 4.3.3.2 Authentication of Challenge and Response
    private byte[] MAC(byte[] key, byte[] message) {
        final var cipher = new DESEngine();
        final var mac = new ISO9797Alg3Mac(cipher, new ISO7816d4Padding());
        final var buffer = new byte[mac.getMacSize()];
        mac.init(new DESedeParameters(key));
        mac.update(message, 0, message.length);
        mac.doFinal(buffer, 0);
        return buffer;
    }

    private byte[] concat(byte[] first, byte[]... rest) {

        final var c = Arrays.copyOf(first, Stream.of(rest)
                .map(a -> a.length)
                .reduce(first.length, Integer::sum)
        );
        var offset = first.length;
        for (final var a : rest) {
            System.arraycopy(a, 0, c, offset, a.length);
            offset += a.length;
        }
        return c;
    }

    private byte[] xor(byte[] a, byte[] b) {

        assertThat(a.length, equalTo(b.length));
        final var out = Arrays.copyOf(a, a.length);
        for (var i = 0; i < out.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    private byte[] getChallenge() {
        return Hex.decode("4608F91988702212");
    }

    private byte[] externalAuthenticate(byte[] commandData) throws InvalidCipherTextException {

        final var Kenc = Hex.decode("AB94FDECF2674FDFB9B391F85D7F76F2");
        final var Kmac = Hex.decode("7962D9ECE03D1ACD4C76089DCE131543");

        final var Eifd = Arrays.copyOf(commandData, 32);
        final var Mifd = Arrays.copyOfRange(commandData, 32, commandData.length);
        assertThat(MAC(Kmac, Eifd), equalTo(Mifd));

        final var S = D(Kenc, Eifd);

        final var RNDifd = Arrays.copyOfRange(S, 0, 8);
        final var RNDic = Arrays.copyOfRange(S, 8, 16);
        assertThat(RNDic, equalTo(getChallenge()));

        final var Kic = Hex.decode("0B4F80323EB3191CB04970CB4052790B");

        final var R = concat(RNDic, RNDifd, Kic);
        assertThat(R, equalTo(Hex.decode("4608F91988702212 781723860C06C226 0B4F80323EB3191CB04970CB4052790B")));

        final var Eic = E(Kenc, R);
        assertThat(Eic, equalTo(Hex.decode("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F")));

        final var Mic = MAC(Kmac, Eic);
        assertThat(Mic, equalTo(Hex.decode("2F2D235D074D7449")));

        final var responseData = concat(Eic, Mic);
        assertThat(responseData, equalTo(Hex.decode("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449")));

        return responseData;
    }

    @Test
    public void testBAC() throws Exception {

        final var Kenc = Hex.decode("AB94FDECF2674FDFB9B391F85D7F76F2");
        final var Kmac = Hex.decode("7962D9ECE03D1ACD4C76089DCE131543");

        final var RNDic = getChallenge();
        final var RNDifd = Hex.decode("781723860C06C226");
        final var Kifd = Hex.decode("0B795240CB7049B01C19B33E32804F0B");

        final var S = concat(RNDifd, RNDic, Kifd);
        assertThat(S, equalTo(Hex.decode("781723860C06C226 4608F91988702212 0B795240CB7049B01C19B33E32804F0B")));

        final var Eifd = E(Kenc, S);
        assertThat(Eifd, equalTo(Hex.decode("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2")));

        final var Mifd = MAC(Kmac, Eifd);
        assertThat(Mifd, equalTo(Hex.decode("5F1448EEA8AD90A7")));

        final var commandData = concat(Eifd, Mifd);
        assertThat(commandData, equalTo(Hex.decode("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7")));

        final var responseData = externalAuthenticate(commandData);

        final var Eic = Arrays.copyOf(responseData, 32);
        final var Mic = Arrays.copyOfRange(responseData, 32, commandData.length);
        assertThat(MAC(Kmac, Eic), equalTo(Mic));

        final var R = D(Kenc, Eic);
        assertThat(Arrays.copyOfRange(R, 8, 16), equalTo(RNDifd));

        final var Kic = Arrays.copyOfRange(R, 16, 32);
        final var Kseed = xor(Kifd, Kic);
        assertThat(Kseed, equalTo(Hex.decode("0036D272F5C350ACAC50C3F572D23600")));

        final var KSenc = KDF(Kseed, new byte[]{0x00, 0x00, 0x00, 0x01});
        assertThat(KSenc, equalTo(Hex.decode("979EC13B1CBFE9DCD01AB0FED307EAE5")));

        final var KSmac = KDF(Kseed, new byte[]{0x00, 0x00, 0x00, 0x02});
        assertThat(KSmac, equalTo(Hex.decode("F1CB1F1FB5ADF208806B89DC579DC1F8")));

        // ICAO 9303 Part 11 section 9.8.6.3 Send Sequence Counter
        final var SSC = concat(Arrays.copyOfRange(RNDic, 4, 8), Arrays.copyOfRange(RNDifd, 4, 8));
        assertThat(SSC, equalTo(Hex.decode("887022120C06C226")));
    }
}
