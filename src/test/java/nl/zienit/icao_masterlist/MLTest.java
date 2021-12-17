package nl.zienit.icao_masterlist;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

// https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf
public class MLTest {

    final static Date TODAY = new Date(1639759523207L); // 17-12-2021

    final static DateFormat DF = new SimpleDateFormat("dd-MM-yyyy");

    private Certificate loadNLCSCACertificate() throws IOException {
        try (final var fis = getClass().getClassLoader().getResourceAsStream("(210621000000Z-340630000000Z) Serialnumber=6,CN=CSCA NL,OU=Kingdom of the Netherlands,O=Kingdom of the Netherlands,C=NL.cer");
             final var ais = new ASN1InputStream(fis)
        ) {
            return Certificate.getInstance(ais.readObject());
        }
    }

    @Test
    public void testNLCSCACertificate() throws Exception {

        final var cscaCert = loadNLCSCACertificate();
        final var cscaCertHolder = new X509CertificateHolder(cscaCert);

        // signature of self-signed CSCA certificate valid?
        final var isSignatureValid = cscaCertHolder.isSignatureValid(
                new JcaContentVerifierProviderBuilder().build(cscaCertHolder)
        );
        assertThat(isSignatureValid, equalTo(true));

        final var isValid = cscaCertHolder.isValidOn(TODAY);
        assertThat(isValid, equalTo(true));
    }

    private ContentInfo loadNLMasterList() throws IOException {
        // ML downloaded from https://www.npkd.nl/masterlist.html
        try (final var fis = getClass().getClassLoader().getResourceAsStream("NL_MASTERLIST_20211207.mls");
             final var ais = new ASN1InputStream(fis)
        ) {
            return ContentInfo.getInstance(ais.readObject());
        }
    }

    @Test
    // ICAO 9303 Part 12, section 9 CSCA MASTER LIST STRUCTURE
    public void testReadNLMasterList() throws Exception {

        // ICAO 9303 Part 12, section 9: Master Lists are implemented as instances of the ContentInfo Type, as specified in [RFC 5652].
        final var ci = loadNLMasterList();

        //  ICAO 9303 Part 12, section 9: The ContentInfo MUST contain a single instance of the SignedData
        assertThat(ci.getContentType(), equalTo(CMSObjectIdentifiers.signedData));
        final var sd = SignedData.getInstance(ci.getContent());

        //  ICAO 9303 Part 12, Table 18: Version = v3
        assertThat(sd.getVersion().intValueExact(), equalTo(3));

        final var cmsSignedData = new CMSSignedData(ci);
        final var signerCerts = cmsSignedData.getCertificates();
        final var signerInfos = cmsSignedData.getSignerInfos();

        // ICAO 9303 Part 12, Table 18: It is RECOMMENDED that States only provide 1 signerinfo within this field.
        // Note: The semantics of multiple signerinfo are unspecified in RFC5662 and ICAO 9303 Part 12, so processing
        // only the first seems reasonable.
        assertThat(signerInfos.size(), greaterThan(0));
        final var signerInfo = signerInfos.getSigners().iterator().next();

        // ICAO 9303 Part 12, Table 18: The Master List Signer certificate MUST be included
        final var matches = signerCerts.getMatches(signerInfo.getSID());
        assertThat(matches.size(), equalTo(1));
        final var masterListSignerCert = (X509CertificateHolder) matches.iterator().next();

        final var isSignerInfoVerified = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(masterListSignerCert));
        assertThat(isSignerInfoVerified, equalTo(true));

        final var nlCSCACert = loadNLCSCACertificate();
        // assert that cscaCert public key was used to sign masterListSignerCert
        assertThat(AuthorityKeyIdentifier.fromExtensions(masterListSignerCert.getExtensions()).getKeyIdentifier(),
                equalTo(SubjectKeyIdentifier.fromExtensions(nlCSCACert.getTBSCertificate().getExtensions()).getKeyIdentifier()));

        final var certPath = CertificateFactory.getInstance("X.509").generateCertPath(
                List.of(
                        new JcaX509CertificateConverter()
                                .getCertificate(masterListSignerCert)
                )
        );

        final var trustAnchors = Collections.singleton(
                new TrustAnchor(
                        new JcaX509CertificateConverter()
                                .getCertificate(new X509CertificateHolder(nlCSCACert))
                        , null
                )
        );

        final var certPathValidator = CertPathValidator.getInstance("PKIX");
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);
        params.setDate(TODAY);

        // note: exception is thrown if validation fails
        final var result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, params);

        final var eci = sd.getEncapContentInfo();

        //  ICAO 9303 Part 12, Table 18: eContentType = id-icao-cscaMasterList
        assertThat(eci.getContentType(), equalTo(ICAOObjectIdentifiers.id_icao_cscaMasterList));
        final var ml = CscaMasterList.getInstance(
                ((ASN1OctetString) eci.getContent()).getOctets()
        );

        final var cscaCerts = ml.getCertStructs();

        System.out.println("\"Issuer\",\"Issuer.CountryName\",\"StartDate\",\"EndDate\",\"CRL1\",\"CRL2\",\"CRL3\",\"CRL4\"");
        for (final var cert : cscaCerts) {
            final var issuer = cert.getIssuer();

            // NL Master List contains only (self signed) CSCA Certificates (no CSCA Link Certificates)
            assertThat(cert.getIssuer(), equalTo(cert.getSubject()));

            // @todo check self signed signature

            System.out.print("\"" + issuer + "\"");
            final var countryName = issuer.getRDNs(X509ObjectIdentifiers.countryName)[0].getFirst().getValue();
            System.out.print(",\"" + countryName + "\"");
            System.out.print(",\"" + DF.format(cert.getStartDate().getDate()) + "\"");
            System.out.print(",\"" + DF.format(cert.getEndDate().getDate()) + "\"");

            final var tbsCert = cert.getTBSCertificate();
            final var extensions = tbsCert.getExtensions();

            // ICAO 9303 Part 12, section 7.1.1 Certificate Profiles: CRLDistributionPoints extension is mandatory
            final var cdp = CRLDistPoint.fromExtensions(extensions);
            final var points = new ArrayList<String>();
            if (cdp != null) { // ICAO 9303 Part 12 Appendix C EARLIER CERTIFICATE PROFILES: CRLDistributionPoints extension was optional
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
    }

    private Certificate fetchCSCACertificate(String countryName, byte[] keyIdentifier) throws IOException {
        final var fis = getClass().getClassLoader().getResourceAsStream("NL_MASTERLIST_20211207.mls");
        final var ais = new ASN1InputStream(fis);
        final var ci = ContentInfo.getInstance(ais.readObject());
        final var sd = SignedData.getInstance(ci.getContent());
        final var eci = sd.getEncapContentInfo();
        final var bytes = ((ASN1OctetString) eci.getContent()).getOctets();
        final var ml = CscaMasterList.getInstance(bytes);
        final var certs = ml.getCertStructs();

        for (final var cert : certs) {
            final var issuer = cert.getIssuer();
            final var cn = issuer.getRDNs(X509ObjectIdentifiers.countryName)[0].getFirst().getValue().toString();
            final var ski = SubjectKeyIdentifier.fromExtensions(cert.getTBSCertificate().getExtensions()).getKeyIdentifier();
            if (cn.equals(countryName) && Arrays.compare(ski, keyIdentifier) == 0) {
                return cert;
            }
        }
        ais.close();
        fis.close();
        throw new NoSuchElementException("CSCA certificate not found");
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
        System.out.println("this update: " + DF.format(tbsCl.getThisUpdate().getDate()));
        System.out.println("next update: " + DF.format(tbsCl.getNextUpdate().getDate()));
        assertThat(tbsCl.getVersion().intValueExact(), equalTo(1)); // 1 == V2

        final var extensions = tbsCl.getExtensions();
        final var aki = AuthorityKeyIdentifier.fromExtensions(extensions);

        // ICAO 9303 Part 12 7.1.4 CRL Profile, Table 10: This MUST be the same value as the subjectKeyIdentifier field in the CRL issuer’s certificate.
        final var csca = fetchCSCACertificate("CO", AuthorityKeyIdentifier.fromExtensions(extensions).getKeyIdentifier());


//        assertThat(aki.getKeyIdentifier(), equalTo(ski.getKeyIdentifier()));

        final var crlHolder = new X509CRLHolder(cl);
        final var isSignatureValid = crlHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csca.getSubjectPublicKeyInfo()));
        assertThat(isSignatureValid, equalTo(true));

        final var entries = tbsCl.getRevokedCertificates();
        for (var e : entries) {
            System.out.print(e.getUserCertificate());
            System.out.println(" " + DF.format(e.getRevocationDate().getDate()));
        }

        ais.close();
        fis.close();
    }
}
