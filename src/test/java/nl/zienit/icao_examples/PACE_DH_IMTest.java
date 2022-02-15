package nl.zienit.icao_examples;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.eac.UnsignedInteger;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
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
public class PACE_DH_IMTest {

    // RFC5114 section 2.1 1024-bit MODP Group with 160-bit Prime Order Subgroup
    final static DomainParameters DOMAIN_DH_1024_160 = newDomainParameters(
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
            new BigInteger(1, Hex.decode("F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353"))
    );

    private static DomainParameters newDomainParameters(BigInteger p, BigInteger g, BigInteger q) {
        return new DomainParameters(
                p,
                g,
                q,
                p.subtract(BigInteger.ONE).multiply(q.modInverse(p)).mod(p), // satisfies the equation p = jq+1, or j = (p-1)/q
                null);
    }

    ;

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

        final var z = Hex.decode("9ABB8864 CA0FF155 1E620D1E F4E13510");
        final var s = new byte[z.length];
        final var Kpi = Hex.decode("591468CD A83D6521 9CCCB856 0233600F");
        final var cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(false, new KeyParameter(Kpi));
        cipher.doFinal(s, cipher.processBytes(z, 0, z.length, s, 0));
        assertThat(s, equalTo(Hex.decode("FA5B7E3E 49753A0D B9178B7B 9BD898C8")));
    }

    private byte[] R_block(BlockCipher bc, byte[] plaintext, byte[] key) throws InvalidCipherTextException {
        final var bbc = new BufferedBlockCipher(new CBCBlockCipher(bc));
        final var ciphertext = new byte[bbc.getOutputSize(plaintext.length)];
        bbc.init(true, new KeyParameter(key));
        bbc.doFinal(ciphertext, bbc.processBytes(plaintext, 0, plaintext.length, ciphertext, 0));
        return ciphertext;
    }

    // ICAO 9303 Part 11, section 4.4.3.3.2 Integrated Mapping: Pseudo-random Number Mapping
    private byte[] R(byte[] s, byte[] t, BlockCipher bc, int k, int p_log2) throws InvalidCipherTextException, IOException {

        // l := bit length of s (note: c0, c1 and the output of R_block() have length l)
        final var l = s.length * 8;
        final var n = (int) Math.ceil((p_log2 + 64.0d) / l);

        final var c0 = Hex.decode(l == 128
                ? "a668892a7c41e3ca739f40b057d85904"
                : "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676"
        );
        final var c1 = Hex.decode(l == 128
                ? "a4e136ac725f738b01c1f60217c188ad"
                : "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517");

        final var x = new ByteArrayOutputStream();

        var k_current = R_block(bc, s, t);
        for (var i = 0; i < n; i++) {
            final var k_truncated = k_current.length > k ? Arrays.copyOf(k_current, k) : k_current;
            final var k_next = R_block(bc, c0, k_truncated);
            x.write(R_block(bc, c1, k_truncated));
            k_current = k_next;
        }

        return x.toByteArray();
    }

    private BigInteger fg(BigInteger x, DomainParameters domain) {
        return x.modPow(domain.getJ(), domain.getP());
    }

    @Test
    public void testMapNonce() throws Exception {

        final var g = DOMAIN_DH_1024_160.getG();
        final var p = DOMAIN_DH_1024_160.getP();
        final var q = DOMAIN_DH_1024_160.getQ();

        // nonces s & t
        final var s = Hex.decode("FA5B7E3E 49753A0D B9178B7B 9BD898C8");
        final var t = Hex.decode("B3A6DB3C 870C3E99 245E0D1C 06B747DE");

        final var R = R(s, t, new AESEngine(), 128, p.bitLength());
        assertThat(R, equalTo(Hex.decode(
                "EAB98D13 E0905295 2AA72990 7C3C9461" +
                        "84DEA0FE 74AD2B3A F506F0A8 3018459C" +
                        "38099CD1 F7FF4EA0 A078DB1F AC136550" +
                        "5E3DC855 00EF95E2 0B4EEF2E 88489233" +
                        "BEE0546B 472F994B 618D1687 02406791" +
                        "DEEF3CB4 810932EC 278F3533 FDB860EB" +
                        "4835C36F A4F1BF3F A0B828A7 18C96BDE" +
                        "88FBA38A 3E6C35AA A1095925 1EB5FC71" +
                        "0FC18725 8995944C 0F926E24 9373F485")));

        final var Rp = new BigInteger(1, R).mod(p);
        assertThat(Rp, equalTo(new BigInteger(1, Hex.decode(
                "A0C7C50C 002061A5 1CC87D25 4EF38068" +
                        "607417B6 EE1B3647 3CFB800D 2D2E5FA2" +
                        "B6980F01 105D24FA B22ACD1B FA5C8A4C" +
                        "093ECDFA FE6D7125 D42A843E 33860383" +
                        "5CF19AFA FF75EFE2 1DC5F6AA 1F9AE46C" +
                        "25087E73 68166FB0 8C1E4627 AFED7D93" +
                        "570417B7 90FF7F74 7E57F432 B04E1236" +
                        "819E0DFE F5B6E77C A4999925 328182D2"))));

        final var g_mapped = fg(Rp, DOMAIN_DH_1024_160);

        // important: g_mapped MUST not be 1
        assertThat(g_mapped, not(equalTo(BigInteger.ONE)));

        assertThat(g_mapped, equalTo(new BigInteger(1, Hex.decode(
                "1D7D767F 11E333BC D6DBAEF4 0E799E7A" +
                        "926B9697 3550656F F3C83072 6D118D61" +
                        "C276CDCC 61D475CF 03A98E0C 0E79CAEB" +
                        "A5BE2557 8BD4551D 0B109032 36F0B0F9" +
                        "76852FA7 8EEA14EA 0ACA87D1 E91F688F" +
                        "E0DFF897 BBE35A47 2621D343 564B262F" +
                        "34223AE8 FC59B664 BFEDFA2B FE7516CA" +
                        "5510A6BB B633D517 EC25D4E0 BBAA16C2"))));
    }

    @Test
    public void testPerformKeyAgreement() throws Exception {

        final var p = DOMAIN_DH_1024_160.getP();

        // Terminal's private key t
        final var t = new BigInteger(1, Hex.decode(
                "4BD0E547 40F9A028 E6A515BF DAF96784" +
                        "8C4F5F5F FF65AA09 15947FFD 1A0DF2FA" +
                        "6981271B C905F355 1457B7E0 3AC3B806" +
                        "6DE4AA40 6C1171FB 43DD939C 4BA16175" +
                        "103BA3DE E16419AA 248118F9 0CC36A3D" +
                        "6F4C3736 52E0C3CC E7F0F1D0 C5425B36" +
                        "00F0F0D6 A67F004C 8BBA33F2 B4733C72" +
                        "52445C1D FC4F1107 203F71D2 EFB28161"));

        // Chip's public key C
        final var C = new BigInteger(1, Hex.decode(
                "928D9A0F 9DBA450F 13FC859C 6F290D1D" +
                        "36E42431 138A4378 500BEB4E 0401854C" +
                        "FF111F71 CB6DC1D0 335807A1 1388CC8E" +
                        "AA87B079 07AAD9FB A6B169AF 6D8C26AF" +
                        "8DDDC39A DC3AD2E3 FF882B84 D23E9768" +
                        "E95A80E4 746FB07A 9767679F E92133B4" +
                        "D379935C 771BD7FB ED6C7BB4 B1708B27" +
                        "5EA75679 524CDC9C 6A91370C C662A2F3"));

        final var K = BigIntegers.asUnsignedByteArray(128, C.modPow(t, p));

        assertThat(K, equalTo(Hex.decode(
                "419410D6 C0A17A4C 07C54872 CE1CBCEB" +
                        "0A2705C1 A434C8A8 9A4CFE41 F1D78124" +
                        "CA7EC52B DE7615E5 345E48AB 1ABB6E7D" +
                        "1D59A57F 3174084D 3CA45703 97C1F622" +
                        "28BDFDB2 DA191EA2 239E2C06 0DBE3BBC" +
                        "23C2FCD0 AF12E0F9 E0B99FCF 91FF1959" +
                        "011D5798 B2FCBC1F 14FCC24E 441F4C8F" +
                        "9B08D977 E9498560 E63E7FFA B3134EA7")));

        final var K_enc = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x01});

        assertThat(K_enc, equalTo(Hex.decode("01AFC10C F87BE36D 8179E873 70171F07")));

        final var K_mac = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x02});

        assertThat(K_mac, equalTo(Hex.decode("23F0FBD0 5FD6C7B8 B88F4C83 09669061")));
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
                "928D9A0F 9DBA450F 13FC859C 6F290D1D" +
                        "36E42431 138A4378 500BEB4E 0401854C" +
                        "FF111F71 CB6DC1D0 335807A1 1388CC8E" +
                        "AA87B079 07AAD9FB A6B169AF 6D8C26AF" +
                        "8DDDC39A DC3AD2E3 FF882B84 D23E9768" +
                        "E95A80E4 746FB07A 9767679F E92133B4" +
                        "D379935C 771BD7FB ED6C7BB4 B1708B27" +
                        "5EA75679 524CDC9C 6A91370C C662A2F3"));
        final var protocol = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.3.2");
        final var Kmac = Hex.decode("23F0FBD0 5FD6C7B8 B88F4C83 09669061");
        final var Td = calculateToken(C, protocol, Kmac);
        assertThat(Td, equalTo(Hex.decode("55D61977 CBF5307E")));

        // Terminals' public key T
        final var T = new BigInteger(1, Hex.decode(
                "0F0CC629 45A80292 51FB7EF3 C094E12E" +
                        "C68E4EF0 7F27CB9D 9CD04C5C 4250FAE0" +
                        "E4F8A951 557E929A EB48E5C6 DD47F2F5" +
                        "CD7C351A 9BD2CD72 2C07EDE1 66770F08" +
                        "FFCB3702 62CF308D D7B07F2E 0DA9CAAA" +
                        "1492344C 85290691 9538C98A 4BA4187E" +
                        "76CE9D87 832386D3 19CE2E04 3C3343AE" +
                        "AE6EDBA1 A9894DC5 094D22F7 FE1351D5"));
        final var Tc = calculateToken(T, protocol, Kmac);
        assertThat(Tc, equalTo(Hex.decode("C2F04230 187E1525")));
    }
}
