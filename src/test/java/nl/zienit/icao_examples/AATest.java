package nl.zienit.icao_examples;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 * Unit tests demonstrating:
 * ICAO
 * Doc 9303
 * Machine Readable Travel Documents
 * Eight Edition, 2021
 * Part 11: Security Mechanisms for MRTDs
 * WORKED EXAMPLE: ACTIVE AUTHENTICATION (INFORMATIVE)
 * <p>
 * The tests focus on the cryptography and on the construction of command- and responseData.
 * The enveloping APDUs are ignored because of their trivial nature.
 * <p>
 */
public class AATest {

    @Test
    public void testAA() throws Exception {

        // Settings: RSA, modulus length (k): 1024 bits, Hash alg: SHA-1 (Lh = 160 bits)
        final var k = 1024;
        final var Lh = 160;

        // No RSA keypair is provided in the worked example. We'll generate a random keypair of appropriate length.
        final var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(k);
        final var kp = kpg.generateKeyPair();
        final var KPUaa = (RSAPublicKey) kp.getPublic();
        final var KPRaa = (RSAPrivateKey) kp.getPrivate();

        // step 1
        final var RNDifd = Hex.decode("F173589974BF40C6");

        // step 3
        final var M2 = RNDifd;

        // step 4
        final var T = new byte[]{(byte) 0xbc};
        final var t = T.length;

        // step 5
        final var c = k - Lh - 8 * t - 4;
        assertThat(c, equalTo(852));
        final var Lm1 = c - 4;

        // step 6
        final var M1 = Hex.decode(
                "9D2784A67F8E7C659973EA1AEA25D95B" +
                        "6C8F91E5002F369F0FBDCE8A3CEC1991" +
                        "B543F1696546C5524CF23A5303CD6C98" +
                        "599F40B79F377B5F3A1406B3B4D8F967" +
                        "84D23AA88DB7E1032A405E69325FA91A" +
                        "6E86F5C71AEA978264C4A207446DAD4E" +
                        "7292E2DCDA3024B47DA8");
        assertThat(M1.length * 8, equalTo(Lm1));

        // step 7
        final var M = Arrays.copyOf(M1, M1.length + M2.length);
        System.arraycopy(M2, 0, M, M1.length, M2.length);

        // step 8
        final var sha1 = new SHA1Digest();
        sha1.update(M, 0, M.length);
        final var H = new byte[sha1.getDigestSize()];
        sha1.doFinal(H, 0);

        assertThat(H, equalTo(Hex.decode("C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127")));

        // step 9
        final var F = new byte[1 + M1.length + H.length + T.length];
        F[0] = 0x6a;
        System.arraycopy(M1, 0, F, 1, M1.length);
        System.arraycopy(H, 0, F, 1 + M1.length, H.length);
        System.arraycopy(T, 0, F, 1 + M1.length + H.length, T.length);

        assertThat(F, equalTo(Hex.decode(
                "6A9D2784A67F8E7C659973EA1AEA25D9" +
                        "5B6C8F91E5002F369F0FBDCE8A3CEC19" +
                        "91B543F1696546C5524CF23A5303CD6C" +
                        "98599F40B79F377B5F3A1406B3B4D8F9" +
                        "6784D23AA88DB7E1032A405E69325FA9" +
                        "1A6E86F5C71AEA978264C4A207446DAD" +
                        "4E7292E2DCDA3024B47DA8C063AA1E6D" +
                        "22FBD976AB0FE73D94D2D9C6D88127BC")));

        // step 10 (given private key d; s := F^d mod n)
        final var s = new BigInteger(1, F).modPow(KPRaa.getPrivateExponent(), KPRaa.getModulus());

        // step 12 (given public key e; F := s^e mod n)
        final var F_star = BigIntegers.asUnsignedByteArray(s.modPow(KPUaa.getPublicExponent(), KPUaa.getModulus()));
        assertThat(F, equalTo(F_star));

        // step 13
        final var T_star = F_star[F_star.length - 1];
        assertThat(T_star, equalTo((byte) 0xbc));

        // step 14
        final var D = Arrays.copyOfRange(F_star, 1 + Lm1 / 8, F_star.length - 1);
        assertThat(D, equalTo(Hex.decode("C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127")));

        // step 15
        final var M1_star = Arrays.copyOfRange(F_star, 1, 1 + Lm1 / 8);
        assertThat(M1_star, equalTo(Hex.decode(
                "9D2784A67F8E7C659973EA1AEA25D95B" +
                        "6C8F91E5002F369F0FBDCE8A3CEC1991" +
                        "B543F1696546C5524CF23A5303CD6C98" +
                        "599F40B79F377B5F3A1406B3B4D8F967" +
                        "84D23AA88DB7E1032A405E69325FA91A" +
                        "6E86F5C71AEA978264C4A207446DAD4E" +
                        "7292E2DCDA3024B47DA8")));

        // step 16
        final var M_star = Arrays.copyOf(M1_star, M1_star.length + RNDifd.length);
        System.arraycopy(RNDifd, 0, M_star, M1_star.length, RNDifd.length);

        assertThat(M_star, equalTo(Hex.decode(
                "9D2784A67F8E7C659973EA1AEA25D95B" +
                        "6C8F91E5002F369F0FBDCE8A3CEC1991" +
                        "B543F1696546C5524CF23A5303CD6C98" +
                        "599F40B79F377B5F3A1406B3B4D8F967" +
                        "84D23AA88DB7E1032A405E69325FA91A" +
                        "6E86F5C71AEA978264C4A207446DAD4E" +
                        "7292E2DCDA3024B47DA8F173589974BF" +
                        "40C6")));

        // step 17
        sha1.reset();
        sha1.update(M_star, 0, M_star.length);
        final var D_star = new byte[sha1.getDigestSize()];
        sha1.doFinal(D_star, 0);

        // step 18
        assertThat(D,equalTo(D_star));
    }
}
