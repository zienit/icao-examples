package nl.zienit.icao_masterlist;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class MLTest {

    @Test
    public void testReadML() throws IOException {

        // ML downloaded from https://www.npkd.nl/masterlist.html
        final var fis = new FileInputStream(System.getProperty("user.home") + "/Downloads/NL_MASTERLIST_20211207.mls");
        final var ais = new ASN1InputStream(fis);
        final var ci = ContentInfo.getInstance(ais.readObject());
        final var sd = SignedData.getInstance(ci.getContent());
        assertThat(sd.getVersion().intValueExact(), equalTo(3));
        final var eci = sd.getEncapContentInfo();
        assertThat(eci.getContentType(), equalTo(ICAOObjectIdentifiers.id_icao_cscaMasterList));
        final var bytes = ((ASN1OctetString) eci.getContent()).getOctets();
        final var ml = CscaMasterList.getInstance(bytes);
        final var certs = ml.getCertStructs();

        final var df = new SimpleDateFormat("dd-MM-yyyy");

        System.out.println("\"Issuer\",\"Issuer.CountryName\",\"StartDate\",\"EndDate\"");
        for (final var cert : certs) {
            final var issuer = cert.getIssuer();

            assertThat(cert.getIssuer(), equalTo(cert.getSubject()));

            System.out.print("\"" + issuer + "\"");
            final var countryName = issuer.getRDNs(X509ObjectIdentifiers.countryName)[0].getFirst().getValue();
            System.out.print(",\"" + countryName + "\"");
            System.out.print(",\"" + df.format(cert.getStartDate().getDate()) + "\"");
            System.out.println(",\"" + df.format(cert.getEndDate().getDate()) + "\"");
        }
        ais.close();
        fis.close();
    }
}
