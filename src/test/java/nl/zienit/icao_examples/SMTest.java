package nl.zienit.icao_examples;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.Matchers;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.Function;

import static org.junit.Assert.assertThat;

public class SMTest {

    private final byte[] K_enc = Hex.decode("979EC13B1CBFE9DCD01AB0FED307EAE5");
    private final byte[] K_mac = Hex.decode("F1CB1F1FB5ADF208806B89DC579DC1F8");
    private final Function<byte[], byte[]> Enc = data -> encrypt3DESCBC(K_enc, data);
    private final Function<byte[], byte[]> Mac = data -> mac3DESCBC(K_mac, data);
    private final Function<byte[], byte[]> pad = data -> pad(data, 8);
    private final Function<BigInteger, byte[]> ssc = counter -> ssc(counter, 8);

    private byte[] pad(byte[] data, int blocksize) {

        final var l = (blocksize - data.length % blocksize);
        if (l == blocksize) {
            return data;
        }
        final byte[] padded = Arrays.copyOf(data, data.length + l);
        padded[data.length] = (byte) 0x80;
        return padded;
    }

    private byte[] concat(byte[] a, byte[] b) {
        final var buffer = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, buffer, a.length, b.length);
        return buffer;
    }

    private byte[] concat(byte a, byte[] b) {
        return concat(new byte[]{a}, b);
    }

    private byte[] ssc(BigInteger value, int blocksize) {
        final var buffer = value.toByteArray();
        if (buffer.length > blocksize) {
            // Note: BigInteger.toByteArray() returns two's-complement representation: If the BigInteger is positive,
            // and the first bit of the byte array produced is 1, a 0x00 byte is prepended. This extra byte must be
            // dropped.
            return Arrays.copyOfRange(buffer, buffer.length - blocksize, buffer.length);
        }
        if (buffer.length < 8) {
            return concat(new byte[blocksize - buffer.length], buffer);
        }
        return buffer;
    }

    private byte[] encrypt3DESCBC(byte[] key, byte[] plaintext) {
        assertThat(DESedeParameters.isReal2Key(key, 0), Matchers.equalTo(true));
        try {
            final var cipher = new BufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
            cipher.init(true, new DESedeParameters(key));
            final var ciphertext = new byte[plaintext.length];
            cipher.doFinal(ciphertext, cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0));
            return ciphertext;
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] mac3DESCBC(byte[] key, byte[] message) {
        final var cipher = new DESEngine();
//        final var mac = new ISO9797Alg3Mac(cipher, new ISO7816d4Padding());
        final var mac = new ISO9797Alg3Mac(cipher);
        final var buffer = new byte[mac.getMacSize()];
        mac.init(new DESedeParameters(key));
        mac.update(message, 0, message.length);
        mac.doFinal(buffer, 0);
        return buffer;
    }

    @Test
    public void testSelectEFCOM() throws Exception {

        final var cmdHeader = new byte[]{0x00 | 0x0c, (byte) 0xa4, 0x02, 0x0c};

        final var paddedData = pad.apply(new byte[]{0x01, 0x1e});

        final var encryptedData = Enc.apply(paddedData);

        final var DO87 = new DERTaggedObject(
                false,
                0x07,
                new DEROctetString(concat((byte) 0x01, encryptedData))
        ).getEncoded();

        final var M = concat(pad.apply(cmdHeader), DO87);
        assertThat(M, Matchers.equalTo(Hex.decode("0CA4020C800000008709016375432908C044F6")));

        var counter = new BigInteger(1, Hex.decode("887022120C06C227"));

        final var N = pad.apply(concat(ssc.apply(counter), M));
        assertThat(N, Matchers.equalTo(Hex.decode("887022120C06C2270CA4020C80000000 8709016375432908C044F68000000000")));

        final var CC = Mac.apply(N);

        final var DO8E = new DERTaggedObject(
                false,
                0x0E,
                new DEROctetString(CC)
        ).getEncoded();
        assertThat(DO8E, Matchers.equalTo(Hex.decode("8E08BF8B92D635FF24F8")));

        final var protectedAPDU = concat(
                concat(
                        cmdHeader,
                        concat(
                                (byte) (DO87.length + DO8E.length),
                                concat(DO87, DO8E)
                        )
                ),
                new byte[]{0x00}
        );

        assertThat(protectedAPDU, Matchers.equalTo(Hex.decode("0CA4020C158709016375432908C0 44F68E08BF8B92D635FF24F800")));

        final var responseAPDU = Hex.decode("990290008E08FA855A5D4C50A8ED9000");

        final var input = new ASN1InputStream(responseAPDU);

        final var DO99 = ASN1TaggedObject.getInstance(input.readObject());
        final var _DO8E = ASN1TaggedObject.getInstance(input.readObject());
        assertThat(DO99.getTagNo(), Matchers.equalTo(0x19));
        assertThat(_DO8E.getTagNo(), Matchers.equalTo(0x0e));
        counter = counter.add(BigInteger.ONE);

        final var K = pad.apply(concat(ssc.apply(counter), DO99.getEncoded()));

        assertThat(K, Matchers.equalTo(Hex.decode("887022120C06C2289902900080000000")));

        final var _CC = Mac.apply(K);
        assertThat(_CC, Matchers.equalTo(ASN1OctetString.getInstance(_DO8E.getObject()).getOctets()));
    }

    @Test
    public void testRead4Bytes() throws Exception {

        final var cmdHeader = new byte[]{0x00 | 0x0c, (byte) 0xb0, 0x00, 0x00};

//        final var paddedData = pad.apply(new byte[]{0x01, 0x1e});
//
//        final var encryptedData = Enc.apply(paddedData);

        final var DO97 = new DERTaggedObject(
                false,
                0x17,
                new DEROctetString(new byte[]{0x04})
        ).getEncoded();

        final var M = concat(pad.apply(cmdHeader), DO97);
        assertThat(M, Matchers.equalTo(Hex.decode("0CB0000080000000970104")));

        var counter = new BigInteger(1, Hex.decode("887022120C06C229"));

        final var N = pad.apply(concat(ssc.apply(counter), M));
        assertThat(N, Matchers.equalTo(Hex.decode("887022120C06C2290CB00000 800000009701048000000000")));

        final var CC = Mac.apply(N);

        final var DO8E = new DERTaggedObject(
                false,
                0x0E,
                new DEROctetString(CC)
        ).getEncoded();
        assertThat(DO8E, Matchers.equalTo(Hex.decode("8E08ED6705417E96BA55")));

        final var protectedAPDU = concat(
                concat(
                        cmdHeader,
                        concat(
                                (byte) (DO97.length + DO8E.length),
                                concat(DO97, DO8E)
                        )
                ),
                new byte[]{0x00}
        );

        assertThat(protectedAPDU, Matchers.equalTo(Hex.decode("0CB000000D9701048E08ED6705417E96BA5500")));

        final var responseAPDU = Hex.decode("8709019FF0EC34F992265199029000 8E08AD55CC17140B2DED9000");

        final var input = new ASN1InputStream(responseAPDU);

        final var DO87 = ASN1TaggedObject.getInstance(input.readObject());
        final var DO99 = ASN1TaggedObject.getInstance(input.readObject());
        final var _DO8E = ASN1TaggedObject.getInstance(input.readObject());
        assertThat(DO87.getTagNo(), Matchers.equalTo(0x07));
        assertThat(DO99.getTagNo(), Matchers.equalTo(0x19));
        assertThat(_DO8E.getTagNo(), Matchers.equalTo(0x0e));
        counter = counter.add(BigInteger.ONE);

        final var K = pad.apply(concat(ssc.apply(counter), concat(DO87.getEncoded(), DO99.getEncoded())));

        assertThat(K, Matchers.equalTo(Hex.decode("887022120C06C22A8709019F F0EC34F99226519902900080")));

        final var _CC = Mac.apply(K);
        assertThat(_CC, Matchers.equalTo(ASN1OctetString.getInstance(_DO8E.getObject()).getOctets()));
    }
}
