package nl.logius.digid;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.Assert.assertThat;

/**
 * Unit test for simple App.
 */
public class AppTest {
    @Before
    public void setup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Security.setProperty("crypto.policy", "unlimited");
    }

    @Test
    public void testParseCardAccess() throws NoSuchAlgorithmException, IOException {

        final var CardAccess = new byte[]{
                0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00,
                0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02,
                0x02, 0x01, 0x02, 0x02, 0x01, 0x0D
        };

        final var id_PACE = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4");

        final var securityInfos = ASN1Set.getInstance(CardAccess);

        final var paceInfo = Stream.iterate(0, i -> i < securityInfos.size(), i -> i + 1)
                .map(i -> ASN1Sequence.getInstance(securityInfos.getObjectAt(i)))
                .filter(securityInfo -> ASN1ObjectIdentifier.getInstance(securityInfo.getObjectAt(0)).on(id_PACE))
                .findFirst().get();

        System.out.println(ASN1Dump.dumpAsString(securityInfos));
    }

    @Test
    public void testKpi() {

        final var documentNumber = "T220001293";
        final var dateOfBirth = "6408125";
        final var dateOfExpiry = "1010318";

        final var mrzInfo = (documentNumber + dateOfBirth + dateOfExpiry).getBytes();

        final var sha1 = new SHA1Digest();
        sha1.update(mrzInfo, 0, mrzInfo.length);
        final var pi = new byte[sha1.getDigestSize()];
        sha1.doFinal(pi, 0);

        assertThat(pi, Matchers.equalTo(Hex.decode("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD")));

        // assume selected cipher = AES, keylength = 128
        sha1.reset();
        sha1.update(pi, 0, pi.length);
        sha1.update(new byte[]{0x00, 0x00, 0x00, 0x03}, 0, 4);
        final var digest = new byte[sha1.getDigestSize()];
        sha1.doFinal(digest, 0);
        final var Kpi = Arrays.copyOf(digest, 16);

        assertThat(Kpi, Matchers.equalTo(Hex.decode("89DED1B2 6624EC1E 634C1989 302849DD")));
    }

    @Test
    public void testEncryptedNonce() throws InvalidCipherTextException {

        final var APDU_RESPONSE = Hex.decode("7C 12 80 10 95 A3 A0 16 52 2E E9 8D 01 E7 6C B6 B9 8B 42 C3 90 00");

        final var authTemplate = ASN1ApplicationSpecific.getInstance(Arrays.copyOf(APDU_RESPONSE, APDU_RESPONSE.length - 2));
        assertThat(authTemplate.getApplicationTag(), Matchers.equalTo(0x7c & 0x1f));
        System.out.println(ASN1Dump.dumpAsString(authTemplate));

        final var authObject = ASN1TaggedObject.getInstance(authTemplate.getContents());
        assertThat(authObject.getTagNo(), Matchers.equalTo(0x80 & 0x1f));
        assertThat(authObject.isExplicit(), Matchers.equalTo(false));

        System.out.println(authObject.getObject().getClass().getName());

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
    public void testGenKeyPairECDHSharedSecret() throws Exception {

        final AlgorithmParameterSpec spec = new ECGenParameterSpec("BrainpoolP256r1");
        final var gen = KeyPairGenerator.getInstance("ECDH", "BC");
        gen.initialize(spec, new SecureRandom());
        final var digid = gen.generateKeyPair();
        final var chip = gen.generateKeyPair();

        final var ecdh = KeyAgreement.getInstance("ECDH", "BC");
        ecdh.init(digid.getPrivate());
        ecdh.doPhase(chip.getPublic(), true);
        final var a = ecdh.generateSecret();

        ecdh.init(chip.getPrivate());
        ecdh.doPhase(digid.getPublic(), true);
        final var b = ecdh.generateSecret();

        assertThat(a, Matchers.equalTo(b));

        final var gen2 = new ECKeyPairGenerator();
        X9ECParameters brainpoolP256r1 = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("BrainpoolP256r1");
        final var domainParms = new ECDomainParameters(brainpoolP256r1.getCurve(), brainpoolP256r1.getG(), brainpoolP256r1.getN(), brainpoolP256r1.getH(), brainpoolP256r1.getSeed());
        gen2.init(new ECKeyGenerationParameters(domainParms, new SecureRandom()));
        final var digid2 = gen2.generateKeyPair();
        System.out.println(digid2.getPublic());
        final var ecdh2 = new ECDHBasicAgreement();

    }

    @Test
    public void testMapNonce() throws Exception {

        // Chip's public key C
        final var C_data = Hex.decode("04 824FBA91 C9CBE26B EF53A0EB E7342A3B F178CEA9 F45DE0B7 0AA60165 1FBA3F57 30D8C879 AAA9C9F7 3991E61B 58F4D52E B87A0A0C 709A49DC 63719363 CCD13C54");
        // Terminal's private key t
        final var t_data = Hex.decode("7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C F21F249D 953BC46F 4C6E1925 9C010F99");

        final var params = ECNamedCurveTable.getParameterSpec("BrainpoolP256r1");

        final var C_spec = new ECPublicKeySpec(params.getCurve().decodePoint(C_data), params);
        final var t_spec = new ECPrivateKeySpec(new BigInteger(t_data), params);
//        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
//        final var C = kf.generatePublic(C_spec);
//        final var t = kf.generatePrivate(t_spec);

        // H := C * t
        final var H = C_spec.getQ().multiply(t_spec.getD());

        assertThat(H.getEncoded(false), Matchers.equalTo(Hex.decode("04 60332EF2 450B5D24 7EF6D386 8397D398 852ED6E8 CAF6FFEE F6BF85CA 57057FD5 0840CA74 15BAF3E4 3BD414D3 5AA4608B 93A2CAF3 A4E3EA4E 82C9C13D 03EB7181")));

        // G' := G * s + H
        final var s = new BigInteger(Hex.decode("3F00C4D3 9D153F2B 2A214A07 8D899B22"));
        final var G = params.getG();
        final var Gmapped = G.multiply(s).add(H);

        assertThat(Gmapped.getEncoded(false), Matchers.equalTo(Hex.decode("04 8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2 8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522")));

        // command data (Terminal public key = G * Terminal private key)
        final var commandData = new DLApplicationSpecific(0x1c,
                new DLTaggedObject(
                        false,
                        0x01,
                        new DEROctetString(G.multiply(t_spec.getD()).getEncoded(false))
                )
        );

        assertThat(commandData.getEncoded(), Matchers.equalTo(Hex.decode("7c 43 81 41 04 7acf3efc982ec45565a4b155129efbc74650dcbfa6362d896fc70262e0c2cc5e544552dcb6725218799115b55c9baa6d9f6bc3a9618e70c25af71777a9c4922d")));
    }
}
