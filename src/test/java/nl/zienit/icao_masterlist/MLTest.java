package nl.zienit.icao_masterlist;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

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

        System.out.println("\"Issuer\",\"Issuer.CountryName\",\"StartDate\",\"EndDate\",\"CRL1\",\"CRL2\",\"CRL3\",\"CRL4\"");
        for (final var cert : certs) {
            final var issuer = cert.getIssuer();

            assertThat(cert.getIssuer(), equalTo(cert.getSubject()));

            System.out.print("\"" + issuer + "\"");
            final var countryName = issuer.getRDNs(X509ObjectIdentifiers.countryName)[0].getFirst().getValue();
            System.out.print(",\"" + countryName + "\"");
            System.out.print(",\"" + df.format(cert.getStartDate().getDate()) + "\"");
            System.out.print(",\"" + df.format(cert.getEndDate().getDate()) + "\"");

            final var tbsCert = cert.getTBSCertificate();
            final var extensions = tbsCert.getExtensions();

            // according to ICAO 9303 Part 12, section 7.1.1 Certificate Profiles, CRLDistributionPoints extension is mandatory
            final var cdp = CRLDistPoint.fromExtensions(extensions);
            final var points = new ArrayList<String>();
            if (cdp != null) { // ICAO 9303 Part 12 Appendix C EARLIER CERTIFICATE PROFILES, CRLDistributionPoints extension was optional
                for (var dp : cdp.getDistributionPoints()) {
                    assertThat(dp.getDistributionPoint().getType(), equalTo(DistributionPointName.FULL_NAME));
                    for (var name : ((GeneralNames) dp.getDistributionPoint().getName()).getNames()) {
                        switch (name.getTagNo()) {
                            case GeneralName.directoryName:
                            case GeneralName.uniformResourceIdentifier:
                                points.add(name.getName().toString());
                                break;
                            default:
                                fail(String.valueOf(name.getTagNo()));
                        }
                    }
                }
            }
            for (var i = 0; i < 4; i++) {
                System.out.print(i < points.size() ? ",\"" + points.get(i) + "\"" : ",\"\"");
            }
            System.out.println();
        }
        ais.close();
        fis.close();
    }
}
