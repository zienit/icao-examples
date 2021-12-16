package nl.zienit.icao_masterlist;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.Test;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.NoSuchElementException;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

// https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf
public class MLTest {

    final static DateFormat df = new SimpleDateFormat("dd-MM-yyyy");

    @Test
    public void testReadNLMasterList() throws IOException {

        // ML downloaded from https://www.npkd.nl/masterlist.html
        final var fis = getClass().getClassLoader().getResourceAsStream("NL_MASTERLIST_20211207.mls");
        final var ais = new ASN1InputStream(fis);
        final var ci = ContentInfo.getInstance(ais.readObject());
        final var sd = SignedData.getInstance(ci.getContent());
        assertThat(sd.getVersion().intValueExact(), equalTo(3));
        final var eci = sd.getEncapContentInfo();
        assertThat(eci.getContentType(), equalTo(ICAOObjectIdentifiers.id_icao_cscaMasterList));
        final var bytes = ((ASN1OctetString) eci.getContent()).getOctets();
        final var ml = CscaMasterList.getInstance(bytes);
        final var certs = ml.getCertStructs();

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

    private Certificate fetchCurrentCSCA(String countryName) throws IOException {
        final var fis = getClass().getClassLoader().getResourceAsStream("NL_MASTERLIST_20211207.mls");
        final var ais = new ASN1InputStream(fis);
        final var ci = ContentInfo.getInstance(ais.readObject());
        final var sd = SignedData.getInstance(ci.getContent());
        final var eci = sd.getEncapContentInfo();
        final var bytes = ((ASN1OctetString) eci.getContent()).getOctets();
        final var ml = CscaMasterList.getInstance(bytes);
        final var certs = ml.getCertStructs();

        // too simple selection, multiple certs may be valid: the most recent startdate must then be selected (rewrite using streams)
        for (final var cert : certs) {
            final var issuer = cert.getIssuer();
            final var cn = issuer.getRDNs(X509ObjectIdentifiers.countryName)[0].getFirst().getValue().toString();
            final var today = new Date();
            if (cn.equals(countryName) && !today.before(cert.getStartDate().getDate()) && !today.after(cert.getEndDate().getDate())) {
                return cert;
            }
        }
        ais.close();
        fis.close();
        throw new NoSuchElementException("No current CSCA found for cn=" + countryName);
    }

    @Test
    public void testReadCOCertificateRevocationList() throws IOException, OperatorCreationException, CertException {

        // CRL downloaded from https://pkddownload1.icao.int/CRLs/COL.crl
        final var fis = getClass().getClassLoader().getResourceAsStream("COL.crl");
        final var ais = new ASN1InputStream(fis);
        final var cl = CertificateList.getInstance(ais.readObject());
        final var tbsCl = cl.getTBSCertList();
        final var sigAlg = cl.getSignatureAlgorithm();
        final var sigVal = cl.getSignature();

        System.out.println("issuer:      " + tbsCl.getIssuer());
        System.out.println("this update: " + df.format(tbsCl.getThisUpdate().getDate()));
        System.out.println("next update: " + df.format(tbsCl.getNextUpdate().getDate()));
        assertThat(tbsCl.getVersion().intValueExact(), equalTo(1)); // 1 == V2

        final var extensions = tbsCl.getExtensions();
        final var aki = AuthorityKeyIdentifier.fromExtensions(extensions);

        final var csca = fetchCurrentCSCA("CO");
        final var ski = SubjectKeyIdentifier.fromExtensions(csca.getTBSCertificate().getExtensions());

        // ICAO 9303 Part 12 7.1.4 CRL Profile, Table 10: This MUST be the same value as the subjectKeyIdentifier field in the CRL issuer’s certificate.
        assertThat(aki.getKeyIdentifier(), equalTo(ski.getKeyIdentifier()));

        final var crlHolder = new X509CRLHolder(cl);
        final var isSignatureValid = crlHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csca.getSubjectPublicKeyInfo()));
        assertThat(isSignatureValid, equalTo(true));

        final var entries = tbsCl.getRevokedCertificates();
        for (var e : entries) {
            System.out.print(e.getUserCertificate());
            System.out.println(" " + df.format(e.getRevocationDate().getDate()));
        }

        ais.close();
        fis.close();
    }
}
