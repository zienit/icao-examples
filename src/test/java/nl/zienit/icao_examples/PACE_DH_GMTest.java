package nl.zienit.icao_examples;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.eac.UnsignedInteger;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.Matchers;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 * Unit tests demonstrating:
 * ICAO
 * Doc 9303
 * Machine Readable Travel Documents
 * Eighth Edition, 2021
 * Part 11: Security Mechanisms for MRTDs
 * WORKED EXAMPLE: PACE – GENERIC MAPPING (INFORMATIVE)
 * DH based example
 * <p>
 * The tests focus on the cryptography.
 * <p>
 */
public class PACE_DH_GMTest {

    // RFC5114 section 2.1 1024-bit MODP Group with 160-bit Prime Order Subgroup
    final static DomainParameters DOMAIN_DH_1024_160 = new DomainParameters(
            new BigInteger(1, Hex.decode(
                    "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6" +
                            "9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0" +
                            "13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70" +
                            "98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0" +
                            "A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708" +
                            "DF1FB2BC 2E4A4371")),
            new BigInteger(1, Hex.decode(
                    "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F" +
                            "D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213" +
                            "160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1" +
                            "909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A" +
                            "D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24" +
                            "855E6EEB 22B3B2E5")),
            new BigInteger(1, Hex.decode("F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353")),
            null, null
    );

    // KDF(K,c) hardwired for cipher = AES and keylength = 128, as applicable to the ICAO PACE Worked Example
    private byte[] KDF(byte[] K, byte[] c) {

        final var sha1 = new SHA1Digest();
        sha1.update(K, 0, K.length);
        sha1.update(c, 0, 4);
        final var digest = new byte[sha1.getDigestSize()];
        sha1.doFinal(digest, 0);
        return Arrays.copyOf(digest, 16);
    }

    @Test
    public void testEncryptedNonce() throws InvalidCipherTextException {

        final var z = Hex.decode("854D8DF5 827FA685 2D1A4FA7 01CDDDCA");
        final var s = new byte[z.length];
        final var Kpi = Hex.decode("89DED1B2 6624EC1E 634C1989 302849DD");
        final var cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(false, new KeyParameter(Kpi));
        cipher.doFinal(s, cipher.processBytes(z, 0, z.length, s, 0));
        assertThat(s, equalTo(Hex.decode("FA5B7E3E 49753A0D B9178B7B 9BD898C8")));
    }

    @Test
    public void testMapNonce() {

        final var g = DOMAIN_DH_1024_160.getG();
        final var p = DOMAIN_DH_1024_160.getP();

        // nonce s
        final var s = Hex.decode("FA5B7E3E 49753A0D B9178B7B 9BD898C8");

        // Terminal's private key t
        final var t = new BigInteger(1, Hex.decode("5265030F 751F4AD1 8B08AC56 5FC7AC95 2E41618D"));

        // note: Terminal public key T = g^t (mod p)
        final var T = g.modPow(t, p);
        assertThat(T, equalTo(new BigInteger(1, Hex.decode(
                "23FB3749 EA030D2A 25B278D2 A562047A" +
                        "DE3F01B7 4F17A154 02CB7352 CA7D2B3E" +
                        "B71C343D B13D1DEB CE9A3666 DBCFC920" +
                        "B49174A6 02CB4796 5CAA73DC 702489A4" +
                        "4D41DB91 4DE9613D C5E98C94 160551C0" +
                        "DF86274B 9359BC04 90D01B03 AD54022D" +
                        "CB4F57FA D6322497 D7A1E28D 46710F46" +
                        "1AFE710F BBBC5F8B A166F431 1975EC6C"))));

        // Chip's public key C
        final var C = new BigInteger(1, Hex.decode(
                "78879F57 225AA808 0D52ED0F C890A4B2" +
                        "5336F699 AA89A2D3 A189654A F70729E6" +
                        "23EA5738 B26381E4 DA19E004 706FACE7" +
                        "B235C2DB F2F38748 312F3C98 C2DD4882" +
                        "A41947B3 24AA1259 AC22579D B93F7085" +
                        "655AF308 89DBB845 D9E6783F E42C9F24" +
                        "49400306 254C8AE8 EE9DD812 A804C0B6" +
                        "6E8CAFC1 4F84D825 8950A91B 44126EE6"));

        // h := C^t (mod p)
        final var h = C.modPow(t, p);

        assertThat(h, equalTo(new BigInteger(1, Hex.decode(
                "5BABEBEF 5B74E5BA 94B5C063 FDA15F1F" +
                        "1CDE9487 3EE0A5D3 A2FCAB49 F258D07F" +
                        "544F13CB 66658C3A FEE9E727 389BE3F6" +
                        "CBBBD321 28A8C21D D6EEA3CF 7091CDDF" +
                        "B08B8D00 7D40318D CCA4FFBF 51208790" +
                        "FB4BD111 E5A968ED 6B6F08B2 6CA87C41" +
                        "0B3CE0C3 10CE104E ABD16629 AA48620C" +
                        "1279270C B0750C0D 37C57FFF E302AE7F"))));

        // g_mapped := g^s * h (mod p)
        final var g_mapped = g.modPow(new BigInteger(1, s), p).multiply(h).mod(p);

        assertThat(g_mapped, equalTo(new BigInteger(1, Hex.decode(
                "7C9CBFE9 8F9FBDDA 8D143506 FA7D9306" +
                        "F4CB17E3 C71707AF F5E1C1A1 23702496" +
                        "84D64EE3 7AF44B8D BD9D45BF 6023919C" +
                        "BAA027AB 97ACC771 666C8E98 FF483301" +
                        "BFA4872D EDE9034E DFACB708 14166B7F" +
                        "36067682 9B826BEA 57291B5A D69FBC84" +
                        "EF1E7790 32A30580 3F743417 93E86974" +
                        "2D401325 B37EE856 5FFCDEE6 18342DC5"))));
    }

    /**
     * A deviation from the ICAO worked example, but needed in a real implementation of PACE:
     * Generate a random ephemeral DH keypair (K,k).
     */
    @Test
    public void testGenKeyPair() {

        final var gen = new DHKeyPairGenerator();
        final var domain = new DHParameters(
                DOMAIN_DH_1024_160.getP(),
                DOMAIN_DH_1024_160.getG()
        );
        gen.init(new DHKeyGenerationParameters(new SecureRandom(), domain));
        final var keyPair = gen.generateKeyPair();
        final var K = ((DHPublicKeyParameters) keyPair.getPublic()).getY();
        final var k = ((DHPrivateKeyParameters) keyPair.getPrivate()).getX();


        // this MUST always hold: K = G^k (mod p)
        assertThat(DOMAIN_DH_1024_160.getG().modPow(k, DOMAIN_DH_1024_160.getP()), Matchers.equalTo(K));
    }

    @Test
    public void testPerformKeyAgreement() throws Exception {

        final var p = DOMAIN_DH_1024_160.getP();

        // Terminal's private key t
        final var t = new BigInteger(1, Hex.decode("89CCD99B 0E8D3B1F 11E1296D CA68EC53 411CF2CA"));

        // Chip's public key C
        final var C = new BigInteger(1, Hex.decode(
                "075693D9 AE941877 573E634B 6E644F8E" +
                        "60AF17A0 076B8B12 3D920107 4D36152B" +
                        "D8B3A213 F53820C4 2ADC79AB 5D0AEEC3" +
                        "AEFB9139 4DA476BD 97B9B14D 0A65C1FC" +
                        "71A0E019 CB08AF55 E1F72900 5FBA7E3F" +
                        "A5DC4189 9238A250 767A6D46 DB974064" +
                        "386CD456 743585F8 E5D90CC8 B4004B1F" +
                        "6D866C79 CE0584E4 9687FF61 BC29AEA1 "));

        final var K_raw = C.modPow(t, p).toByteArray();
        // Note: BigInteger.toByteArray() returns two's-complement representation: If the BigInteger is positive,
        // and the first bit of the byte array produced is 1, a 0x00 byte is prepended. This extra byte must be
        // dropped.
        final var K = K_raw[0] == 0 ? Arrays.copyOfRange(K_raw, 1, K_raw.length - 1) : K_raw;

        assertThat(K, equalTo(Hex.decode("6BABC7B3 A72BCD7E A385E4C6 2DB2625B" +
                "D8613B24 149E146A 629311C4 CA6698E3" +
                "8B834B6A 9E9CD718 4BA8834A FF5043D4" +
                "36950C4C 1E783236 7C10CB8C 314D40E5" +
                "990B0DF7 013E64B4 549E2270 923D06F0" +
                "8CFF6BD3 E977DDE6 ABE4C31D 55C0FA2E" +
                "465E553E 77BDF75E 3193D383 4FC26E8E" +
                "B1EE2FA1 E4FC97C1 8C3F6CFF FE2607FD ")));

        final var K_enc = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x01});

        assertThat(K_enc, equalTo(Hex.decode("2F7F46AD CC9E7E52 1B45D192 FAFA9126")));

        final var K_mac = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x02});

        assertThat(K_mac, equalTo(Hex.decode("805A1D27 D45A5116 F73C5446 9462B7D8")));
    }

    private byte[] calculateToken(final BigInteger publicKey, final ASN1ObjectIdentifier protocol, final byte[] Kmac) throws IOException {

        final var v = new ASN1EncodableVector();
        v.add(protocol);
        v.add(new UnsignedInteger(0x04, publicKey));

        final var inputData = new DERApplicationSpecific(0x49, v).getEncoded();

        final var aes = new AESEngine();
        final var mac = new CMac(aes);
        final var buffer = new byte[mac.getMacSize()];
        mac.init(new KeyParameter(Kmac));
        mac.update(inputData, 0, inputData.length);
        mac.doFinal(buffer, 0);
        return Arrays.copyOf(buffer, 8);
    }

    @Test
    public void testMutualAuthentication() throws Exception {

        // Chip's public key C
        final var C = new BigInteger(1, Hex.decode(
                "075693D9 AE941877 573E634B 6E644F8E" +
                        "60AF17A0 076B8B12 3D920107 4D36152B" +
                        "D8B3A213 F53820C4 2ADC79AB 5D0AEEC3" +
                        "AEFB9139 4DA476BD 97B9B14D 0A65C1FC" +
                        "71A0E019 CB08AF55 E1F72900 5FBA7E3F" +
                        "A5DC4189 9238A250 767A6D46 DB974064" +
                        "386CD456 743585F8 E5D90CC8 B4004B1F" +
                        "6D866C79 CE0584E4 9687FF61 BC29AEA1 "));
        final var protocol = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.1.2");
        final var Kmac = Hex.decode("805A1D27 D45A5116 F73C5446 9462B7D8");
        final var Td = calculateToken(C, protocol, Kmac);
        System.out.println(Hex.toHexString(Td));
        assertThat(Td, equalTo(Hex.decode("B46DD9BD 4D98381F")));

        // Terminals' public key T
        final var T = new BigInteger(1, Hex.decode(
                "907D89 E2D425A1 78AA81AF 4A7774EC" +
                        "8E388C11 5CAE6703 1E85EECE 520BD911" +
                        "551B9AE4 D04369F2 9A02626C 86FBC674" +
                        "7CC7BC35 2645B616 1A2A42D4 4EDA80A0" +
                        "8FA8D61B 76D3A154 AD8A5A51 786B0BC0" +
                        "71470578 71A92221 2C5F67F4 31731722" +
                        "36B7747D 1671E6D6 92A3C7D4 0A0C3C5C" +
                        "E397545D 015C175E B5130551 EDBC2EE5 D4"));
        final var Tc = calculateToken(T, protocol, Kmac);
        assertThat(Tc, equalTo(Hex.decode("917F37B5 C0E6D8D1")));
    }
}
