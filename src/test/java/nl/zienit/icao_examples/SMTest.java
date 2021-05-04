package nl.zienit.icao_examples;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.Matchers;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.Function;

import static org.junit.Assert.assertThat;

public class SMTest {

    private byte[] pad(byte[] data) {

        final var l = (8 - data.length % 8);
        if (l == 8) {
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

    private byte[] SSC(BigInteger value) {
        final var buffer = value.toByteArray();
        if (buffer.length > 8) {
            // Note: BigInteger.toByteArray() returns two's-complement representation: If the BigInteger is positive,
            // and the first bit of the byte array produced is 1, a 0x00 byte is prepended. This extra byte must be
            // dropped.
            return Arrays.copyOfRange(buffer, buffer.length - 8, buffer.length);
        }
        if (buffer.length < 8) {
            return concat(new byte[8 - buffer.length], buffer);
        }
        return buffer;
    }

    private byte[] encrypt3DESCBC(byte[] key, byte[] plaintext) {
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

        final var K_enc = Hex.decode("979EC13B1CBFE9DCD01AB0FED307EAE5");
        final var K_mac = Hex.decode("F1CB1F1FB5ADF208806B89DC579DC1F8");

        assertThat(DESedeParameters.isReal2Key(K_enc, 0), Matchers.equalTo(true));
        final Function<byte[], byte[]> Enc = data -> encrypt3DESCBC(K_enc, data);
        final Function<byte[], byte[]> Mac = data -> mac3DESCBC(K_mac, data);

        final var cmdHeader = new byte[]{0x0c, (byte) 0xa4, 0x02, 0x0c};

        final var data = pad(new byte[]{0x01, 0x1e});

        final var encryptedData = Enc.apply(data);

        final var DO87 = new DERTaggedObject(
                false,
                0x07,
                new DEROctetString(concat((byte) 0x01, encryptedData))
        ).getEncoded();

        final var M = concat(pad(cmdHeader), DO87);
        assertThat(M, Matchers.equalTo(Hex.decode("0CA4020C800000008709016375432908C044F6")));

        final var ssc = new BigInteger(1, Hex.decode("887022120C06C227"));

        final var N = pad(concat(SSC(ssc), M));
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
                        concat((byte) (DO87.length + DO8E.length), DO87)),
                concat(DO8E, new byte[]{0x00})
        );

        assertThat(protectedAPDU, Matchers.equalTo(Hex.decode("0CA4020C158709016375432908C0 44F68E08BF8B92D635FF24F800")));
    }
}
