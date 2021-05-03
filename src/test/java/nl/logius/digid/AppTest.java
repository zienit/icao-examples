package nl.logius.digid;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.Assert.assertThat;

/**
 * Unit test demonstrating:
 * ICAO
 * Doc 9303
 * Machine Readable Travel Documents
 * Seventh Edition, 2015
 * Part 11: Security Mechanisms for MRTDs
 * WORKED EXAMPLE: PACE – GENERIC MAPPING (INFORMATIVE)
 * ECDH based example
 * <p>
 * The tests focus on the cryptography and on the construction of command- and responseData.
 * The enveloping APDUs are ignored because of their trivial nature.
 * <p>
 * Note that the worked example uses protocol id_PACE_DH_GM_AES_CBC_CMAC_128
 */
public class AppTest {

    @Test
    public void testParseCardAccess() {

        final var CardAccess = new byte[]{
                0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00,
                0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04,
                0x02, 0x01, 0x02, 0x02, 0x01, 0x0D
        };

        final var id_PACE_DH_GM_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.4");

        final var securityInfos = ASN1Set.getInstance(CardAccess);

        final var paceInfo = Stream.iterate(0, i -> i < securityInfos.size(), i -> i + 1)
                .map(i -> ASN1Sequence.getInstance(securityInfos.getObjectAt(i)))
                .filter(securityInfo -> ASN1ObjectIdentifier.getInstance(securityInfo.getObjectAt(0)).equals(id_PACE_DH_GM_AES_CBC_CMAC_256))
                .findFirst();

        assertThat(paceInfo.isPresent(), Matchers.equalTo(true));

        final var parameterId = ASN1Integer.getInstance(paceInfo.get().getObjectAt(2));
        assertThat(parameterId.intValueExact(), Matchers.equalTo(13));
    }

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
    public void testCalculateKpi() {

        final var documentNumber = "T220001293";
        final var dateOfBirth = "6408125";
        final var dateOfExpiry = "1010318";

        final var mrzInfo = (documentNumber + dateOfBirth + dateOfExpiry).getBytes();

        final var sha1 = new SHA1Digest();
        sha1.update(mrzInfo, 0, mrzInfo.length);
        final var pi = new byte[sha1.getDigestSize()];
        sha1.doFinal(pi, 0);

        assertThat(pi, Matchers.equalTo(Hex.decode("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD")));

        final var Kpi = KDF(pi, new byte[]{0x00, 0x00, 0x00, 0x03});

        assertThat(Kpi, Matchers.equalTo(Hex.decode("89DED1B2 6624EC1E 634C1989 302849DD")));
    }

    @Test
    public void testEncryptedNonce() throws InvalidCipherTextException {

        final var responseData = Hex.decode("7C 12 80 10 95 A3 A0 16 52 2E E9 8D 01 E7 6C B6 B9 8B 42 C3");

        final var authTemplate = ASN1ApplicationSpecific.getInstance(responseData);
        assertThat(authTemplate.getApplicationTag(), Matchers.equalTo(0x1c));

        final var authObject = ASN1TaggedObject.getInstance(authTemplate.getContents());
        assertThat(authObject.getTagNo(), Matchers.equalTo(0x00));

        final var z = ASN1OctetString.getInstance(authObject.getObject()).getOctets();
        assertThat(z, Matchers.equalTo(Hex.decode("95 A3 A0 16 52 2E E9 8D 01 E7 6C B6 B9 8B 42 C3")));

        final var s = new byte[z.length];
        final var Kpi = Hex.decode("89DED1B2 6624EC1E 634C1989 302849DD");
        final var cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(false, new KeyParameter(Kpi));
        cipher.doFinal(s, cipher.processBytes(z, 0, z.length, s, 0));
        assertThat(s, Matchers.equalTo(Hex.decode("3F00C4D3 9D153F2B 2A214A07 8D899B22")));
    }

    @Test
    public void testMapNonce() throws Exception {

        // nonce s
        final var s = new BigInteger(1, Hex.decode("3F00C4D3 9D153F2B 2A214A07 8D899B22"));

        // Terminal's private key t
        final var t_data = Hex.decode("7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C F21F249D 953BC46F 4C6E1925 9C010F99");

        final var params = ECNamedCurveTable.getParameterSpec("BrainpoolP256r1");
        final var G = params.getG();

        final var t = new BigInteger(1, t_data);

        // note: Terminal public key = G * t
        final var commandData = new DERApplicationSpecific(0x1c,
                new DERTaggedObject(
                        false,
                        0x01,
                        new DEROctetString(G.multiply(t).normalize().getEncoded(false))
                )
        );

        assertThat(commandData.getEncoded(), Matchers.equalTo(Hex.decode("7c 43 81 41 04 7A CF 3E FC 98 2E C4 55 65 A4 B1 55 12 9E FB C7 46 50 DC BF A6 36 2D 89 6F C7 02 62 E0 C2 CC 5E 54 45 52 DC B6 72 52 18 79 91 15 B5 5C 9B AA 6D 9F 6B C3 A9 61 8E 70 C2 5A F7 17 77 A9 C4 92 2D")));

        final var responseData = Hex.decode("7C 43 82 41 04 824FBA91 C9CBE26B EF53A0EB E7342A3B F178CEA9 F45DE0B7 0AA60165 1FBA3F57 30D8C879 AAA9C9F7 3991E61B 58F4D52E B87A0A0C 709A49DC 63719363 CCD13C54");

        final var authTemplate = ASN1ApplicationSpecific.getInstance(responseData);
        assertThat(authTemplate.getApplicationTag(), Matchers.equalTo(0x1c));

        final var authObject = ASN1TaggedObject.getInstance(authTemplate.getContents());
        assertThat(authObject.getTagNo(), Matchers.equalTo(0x02));

        // Chip's public key C
        final var C_data = ASN1OctetString.getInstance(authObject.getObject()).getOctets();
        final var C = params.getCurve().decodePoint(C_data);

        // H := C * t
        final var H = C.multiply(t).normalize();

        assertThat(H.getEncoded(false), Matchers.equalTo(Hex.decode("04 60332EF2 450B5D24 7EF6D386 8397D398 852ED6E8 CAF6FFEE F6BF85CA 57057FD5 0840CA74 15BAF3E4 3BD414D3 5AA4608B 93A2CAF3 A4E3EA4E 82C9C13D 03EB7181")));

        // G' := G * s + H
        // important note: normalize() maps the point to affine coordinates. To speed up calculations, projected coordinates may
        // or may not have been used instead.
        final var Gmapped = G.multiply(s).add(H).normalize();

        assertThat(Gmapped.getEncoded(false), Matchers.equalTo(Hex.decode("04 8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2 8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522")));
    }

    /**
     * A deviation from the ICAO worked example, but needed in a real implementation of PACE:
     * Generate a random ephemeral EC keypair (P,p).
     */
    @Test
    public void testGenKeyPairECDHSharedSecret() throws Exception {

        final var gen = new ECKeyPairGenerator();
        final var brainpoolP256r1 = ECNamedCurveTable.getParameterSpec("BrainpoolP256r1");
        final var domain = new ECDomainParameters(
                brainpoolP256r1.getCurve(),
                brainpoolP256r1.getG(),
                brainpoolP256r1.getN(),
                brainpoolP256r1.getH(),
                brainpoolP256r1.getSeed()
        );
        gen.init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        final var keyPair = gen.generateKeyPair();
        final var P = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
        final var p = ((ECPrivateKeyParameters) keyPair.getPrivate()).getD();

        // this MUST always hold: P = p * G
        assertThat(brainpoolP256r1.getG().multiply(p).normalize(), Matchers.equalTo(P));
    }

    @Test
    public void testPerformKeyAgreement() throws Exception {

        // Terminal's private key t
        final var t_data = Hex.decode("A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595");

        final var params = ECNamedCurveTable.getParameterSpec("BrainpoolP256r1");
        final var Gmapped = params.getCurve().decodePoint(Hex.decode("04 8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2 8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522"));

        final var t = new BigInteger(1, t_data);

        // note: Terminal public key = G' * t
        final var commandData = new DERApplicationSpecific(0x1c,
                new DERTaggedObject(
                        false,
                        0x03,
                        new DEROctetString(Gmapped.multiply(t).normalize().getEncoded(false))
                )
        );

        assertThat(commandData.getEncoded(), Matchers.equalTo(Hex.decode("7C 43 83 41 04 2D B7 A6 4C 03 55 04 4E C9 DF 19 05 14 C6 25 CB A2 CE A4 87 54 88 71 22 F3 A5 EF 0D 5E DD 30 1C 35 56 F3 B3 B1 86 DF 10 B8 57 B5 8F 6A 7E B8 0F 20 BA 5D C7 BE 1D 43 D9 BF 85 01 49 FB B3 64 62")));

        final var responseData = Hex.decode("7C 43 84 41 04 9E 88 0F 84 29 05 B8 B3 18 1F 7A F7 CA A9 F0 EF B7 43 84 7F 44 A3 06 D2 D2 8C 1D 9E C6 5D F6 DB 77 64 B2 22 77 A2 ED DC 3C 26 5A 9F 01 8F 9C B8 52 E1 11 B7 68 B3 26 90 4B 59 A0 19 37 76 F0 94");

        final var authTemplate = ASN1ApplicationSpecific.getInstance(responseData);
        assertThat(authTemplate.getApplicationTag(), Matchers.equalTo(0x1c));

        final var authObject = ASN1TaggedObject.getInstance(authTemplate.getContents());
        assertThat(authObject.getTagNo(), Matchers.equalTo(0x04));

        // Chip's public key C
        final var C_data = ASN1OctetString.getInstance(authObject.getObject()).getOctets();
        final var C = params.getCurve().decodePoint(C_data);

        final var K = C.multiply(t).normalize().getXCoord().getEncoded();

        assertThat(K, Matchers.equalTo(Hex.decode("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925")));

        final var K_enc = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x01});

        assertThat(K_enc, Matchers.equalTo(Hex.decode("F5F0E35C 0D7161EE 6724EE51 3A0D9A7F")));

        final var K_mac = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x02});

        assertThat(K_mac, Matchers.equalTo(Hex.decode("FE251C78 58B356B2 4514B3BD 5F4297D1")));
    }

    private byte[] calculateToken(final byte[] publicKey, final ASN1ObjectIdentifier protocol, final byte[] Kmac) throws IOException {

        final var v = new ASN1EncodableVector();
        v.add(protocol);
        v.add(new DERTaggedObject(
                false,
                0x06,
                new DEROctetString(publicKey)
        ));

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
        final var C_data = Hex.decode("049E88 0F842905 B8B3181F 7AF7CAA9 F0EFB743 847F44A3 06D2D28C 1D9EC65D F6DB7764 B22277A2 EDDC3C26 5A9F018F 9CB852E1 11B768B3 26904B59 A0193776 F094");
        final var protocol = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2");
        final var Kmac = Hex.decode("FE251C78 58B356B2 4514B3BD 5F4297D1");
        final var Td = calculateToken(C_data, protocol, Kmac);

        assertThat(Td, Matchers.equalTo(Hex.decode("C2B0BD78 D94BA866")));

        final var commandData = new DLApplicationSpecific(0x1c,
                new DERTaggedObject(
                        false,
                        0x05,
                        new DEROctetString(Td)
                )
        );

        assertThat(commandData.getEncoded(), Matchers.equalTo(Hex.decode("7C 0A 85 08 C2 B0 BD 78 D9 4B A8 66")));

        final var responseData = Hex.decode("7C0A86083ABB9674BCE93C08");

        final var authTemplate = ASN1ApplicationSpecific.getInstance(responseData);
        assertThat(authTemplate.getApplicationTag(), Matchers.equalTo(0x1c));

        final var authObject = ASN1TaggedObject.getInstance(authTemplate.getContents());
        assertThat(authObject.getTagNo(), Matchers.equalTo(0x06));

        final var Tc = ASN1OctetString.getInstance(authObject.getObject()).getOctets();
        assertThat(Tc, Matchers.equalTo(Hex.decode("3ABB9674 BCE93C08")));

        // Terminals' public key T
        final var T_data = Hex.decode("042DB7 A64C0355 044EC9DF 190514C6 25CBA2CE A4875488 7122F3A5 EF0D5EDD 301C3556 F3B3B186 DF10B857 B58F6A7E B80F20BA 5DC7BE1D 43D9BF85 0149FBB3 6462");
        final var Tc_verify = calculateToken(T_data, protocol, Kmac);
        assertThat(Tc, Matchers.equalTo(Tc_verify)); // terminal and chip calculated the same value for Tc
    }
}
