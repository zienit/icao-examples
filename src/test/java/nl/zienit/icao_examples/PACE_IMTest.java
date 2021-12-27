package nl.zienit.icao_examples;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 * Unit tests demonstrating:
 * ICAO
 * Doc 9303
 * Machine Readable Travel Documents
 * Seventh Edition, 2015
 * Part 11: Security Mechanisms for MRTDs
 * WORKED EXAMPLE: WORKED EXAMPLE: PACE – INTEGRATED MAPPING
 * ECDH based example
 * <p>
 * The tests focus on the cryptography and on the construction of command- and responseData.
 * The enveloping APDUs are ignored because of their trivial nature.
 * <p>
 */
public class PACE_IMTest {

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

        final var z = Hex.decode("143DC40C 08C8E891 FBED7DED B92B64AD");
        final var s = new byte[z.length];
        final var Kpi = Hex.decode("591468CD A83D6521 9CCCB856 0233600F");
        final var cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(false, new KeyParameter(Kpi));
        cipher.doFinal(s, cipher.processBytes(z, 0, z.length, s, 0));
        assertThat(s, equalTo(Hex.decode("2923BE84 E16CD6AE 529049F1 F1BBE9EB")));
    }

    private byte[] R_block(BlockCipher bc, byte[] plaintext, byte[] key) throws InvalidCipherTextException {
        final var bbc = new BufferedBlockCipher(new CBCBlockCipher(bc));
        final var ciphertext = new byte[bbc.getOutputSize(plaintext.length)];
        bbc.init(true, new KeyParameter(key));
        bbc.doFinal(ciphertext, bbc.processBytes(plaintext, 0, plaintext.length, ciphertext, 0));
        return ciphertext;
    }

    // ICAO 9303 Part 11, section 4.4.3.3.2 Integrated Mapping: Pseudo-random Number Mapping
    public byte[] R(byte[] s, byte[] t, BlockCipher bc, int k, int p_log2) throws InvalidCipherTextException, IOException {

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

    // ICAO 9303 Appendix B to Part 11, POINT ENCODING FOR THE ECDH-INTEGRATED MAPPING (INFORMATIVE)
    // B.2 IMPLEMENTATION FOR AFFINE COORDINATES
    private ECPoint fG(BigInteger t, ECCurve curve) {

        final var p = curve.getField().getCharacteristic();
        final var a = curve.getA().toBigInteger();
        final var b = curve.getB().toBigInteger();
        final var f = curve.getCofactor();

        final var alpha = t.modPow(BigInteger.valueOf(2), p).negate().mod(p);

        final var alphaSquare = alpha.modPow(TWO, p);
        final var alphaPlusAlphaSquare = alpha.add(alphaSquare).mod(p);

        final var X2 = b.negate()
                .multiply(ONE.add(alphaPlusAlphaSquare))
                .multiply(a.multiply(alphaPlusAlphaSquare).modPow(p.subtract(TWO), p))
                .mod(p);

        final var X3 = alpha.multiply(X2).mod(p);
        final var h2 = X2.modPow(BigInteger.valueOf(3), p)
                .add(a.multiply(X2))
                .add(b)
                .mod(p);

        final var U = t.modPow(BigInteger.valueOf(3), p).multiply(h2).mod(p);
        final var pPlusOneOverFour = p.add(ONE).multiply(BigInteger.valueOf(4).modInverse(p)).mod(p);
        final var A = h2.modPow(p.subtract(ONE).subtract(pPlusOneOverFour).mod(p), p);
        final var ASquareTimesH2 = A.modPow(TWO, p).multiply(h2).mod(p);

        final var xy = ASquareTimesH2.equals(ONE)
                ? curve.createPoint(X2, A.multiply(h2).mod(p))
                : curve.createPoint(X3, A.multiply(U).mod(p));

        return (f.equals(ONE) ? xy : xy.multiply(f)).normalize();
    }

    @Test
    public void testMapNonce() throws Exception {

        // Prime p (BrainpoolP256r1)
        final var params = ECNamedCurveTable.getByName("BrainpoolP256r1");
        final var curve = params.getCurve();
        final var p = curve.getField().getCharacteristic();

        // nonces s & t
        final var s = Hex.decode("2923BE84 E16CD6AE 529049F1 F1BBE9EB");
        final var t = Hex.decode("5DD4CBFC 96F5453B 130D890A 1CDBAE32");

        final var R = R(s, t, new AESEngine(), 128, p.bitLength());
        assertThat(R, equalTo(Hex.decode("E4447E2D FB3586BA C05DDB00 156B57FB B2179A39 49294C97 25418980 0C517BAA 8DA0FF39 7ED8C445 D3E421E4 FEB57322")));

        final var Rp = new BigInteger(1, R).mod(p);
        assertThat(Rp, equalTo(new BigInteger(1, Hex.decode("A2F8FF2D F50E52C6 599F386A DCB595D2 29F6A167 ADE2BE5F 2C3296AD D5B7430E"))));

        final var Gmapped = fG(Rp, curve);
        assertThat(Gmapped.getXCoord().getEncoded(), equalTo(Hex.decode("8E82D315 59ED0FDE 92A4D049 8ADD3C23 BABA94FB 77691E31 E90AEA77 FB17D427")));
        assertThat(Gmapped.getYCoord().getEncoded(), equalTo(Hex.decode("4C1AE14B D0C3DBAC 0C871B7F 36081693 64437CA3 0AC243A0 89D3F266 C1E60FAD")));
    }

    @Test
    public void testPerformKeyAgreement() throws Exception {

        final var params = ECNamedCurveTable.getByName("BrainpoolP256r1");
        final var Gmapped = params.getCurve().decodePoint(Hex.decode("04 8E82D315 59ED0FDE 92A4D049 8ADD3C23 BABA94FB 77691E31 E90AEA77 FB17D427 4C1AE14B D0C3DBAC 0C871B7F 36081693 64437CA3 0AC243A0 89D3F266 C1E60FAD"));

        // Terminal's private key t
        final var t = new BigInteger(1, Hex.decode("A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595"));

        // note: Terminal public key T = G' * t
        final var T = Gmapped.multiply(t).normalize();
        assertThat(T.getEncoded(false), equalTo(Hex.decode("04 89CBA23F FE96AA18 D824627C 3E934E54 A9FD0B87 A95D1471 DC1C0ABF DCD640D4 6755DE9B 7B778280 B6BEBD57 439ADFEB 0E21FD4E D6DF4257 8C13418A 59B34C37")));

        // Chip's public key C
        final var C = params.getCurve().decodePoint(Hex.decode("04 67F78E5F 7F768608 2B293E8D 087E0569 16D0F74B C01A5F89 57D0DE45 691E51E8 932B69A9 62B52A09 85AD2C0A 271EE6A1 3A8ADDDC D1A3A994 B9DED257 F4D22753"));

        final var K = C.multiply(t).normalize().getXCoord().getEncoded();

        assertThat(K, equalTo(Hex.decode("4F150FDE 1D4F0E38 E95017B8 91BAE171 33A0DF45 B0D3E18B 60BA7BEA FDC2C713")));

        final var K_enc = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x01});

        assertThat(K_enc, equalTo(Hex.decode("0D3FEB33 251A6370 893D62AE 8DAAF51B")));

        final var K_mac = KDF(K, new byte[]{0x00, 0x00, 0x00, 0x02});

        assertThat(K_mac, equalTo(Hex.decode("B01E89E3 D9E8719E 586B50B4 A7506E0B")));
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
        final var C_data = Hex.decode("04 67F78E5F 7F768608 2B293E8D 087E0569 16D0F74B C01A5F89 57D0DE45 691E51E8 932B69A9 62B52A09 85AD2C0A 271EE6A1 3A8ADDDC D1A3A994 B9DED257 F4D22753");
        final var protocol = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.4.2");
        final var Kmac = Hex.decode("B01E89E3 D9E8719E 586B50B4 A7506E0B");
        final var Td = calculateToken(C_data, protocol, Kmac);
        assertThat(Td, equalTo(Hex.decode("450F02B8 6F6A0909")));

        // Terminals' public key T
        final var T_data = Hex.decode("04 89CBA23F FE96AA18 D824627C 3E934E54 A9FD0B87 A95D1471 DC1C0ABF DCD640D4 6755DE9B 7B778280 B6BEBD57 439ADFEB 0E21FD4E D6DF4257 8C13418A 59B34C37");
        final var Tc = calculateToken(T_data, protocol, Kmac);
        assertThat(Tc, equalTo(Hex.decode("75D4D96E 8D5B0308")));
    }
}
