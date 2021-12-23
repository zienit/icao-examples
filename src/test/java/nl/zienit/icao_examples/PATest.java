package nl.zienit.icao_examples;

import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.util.Formatter;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;

// note: there are some differences between BER-TLV, as defined in ISO/IEC 7816
// for SmartCards, and BER as defined in X.690. In version 1.70 of BC, these differences
// lead to an exception being thrown when parsing Ef.COM. For this reason, two different
// libraries are used. See also this discussion: https://github.com/bcgit/bc-java/issues/1081
public class PATest {

    @Test
    // ICAO 9303 Part 10, section 4.6.2 Document Security Object EF.SOD
    public void testReadSOD() throws Exception {
        try (final var fis = new FileInputStream(System.getProperty("user.home") + "/Documents/passive_auth/efSod");
             final var sod = new TLVInputStream(fis)
        ) {
            assertThat(sod.readTag(), equalTo(0x77));
            sod.readLength();
            final var ci = ContentInfo.getInstance(sod.readValue());
            assertThat(ci.getContentType(), equalTo(CMSObjectIdentifiers.signedData));
            final var sd = SignedData.getInstance(ci.getContent());

            //  ICAO 9303 Part 10, Table 37: Version = v3
            assertThat(sd.getVersion().intValueExact(), equalTo(3));

            final var cmsSignedData = new CMSSignedData(ci);
            final var signerCerts = cmsSignedData.getCertificates();
            final var signerInfos = cmsSignedData.getSignerInfos();

            // ICAO 9303 Part 10, Table 37: It is recommended that States provide only one signerInfo within this field.
            // Note: The semantics of multiple signerinfo are unspecified in RFC5662 and ICAO 9303 Part 12, so processing
            // only the first seems reasonable.
            assertThat(signerInfos.size(), greaterThan(0));
            final var signerInfo = signerInfos.getSigners().iterator().next();

            // ICAO 9303 Part 10, Table 37: States are REQUIRED to include the Document Signer Certificate (CDS) which can
            // be used to verify the signature in the signerInfos field. (i.e. getMatches() MUST find it)
            final var matches = signerCerts.getMatches(signerInfo.getSID());
            assertThat(matches.size(), equalTo(1));
            final var documentSignerCert = (X509CertificateHolder) matches.iterator().next();

            // verify the signerInfo against the public key in the Document Signer certificate
            final var isSignerInfoVerified = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(documentSignerCert));
            assertThat(isSignerInfoVerified, equalTo(true));

            // note: validation of the Document Signer certificate itself is skipped in this test,
            // but MUST be done in production applications.

            final var eci = sd.getEncapContentInfo();

            //  ICAO 9303 Part 10, Table 37: eContentType = id-icao-mrtd-security-ldsSecurityObject
            assertThat(eci.getContentType(), equalTo(ICAOObjectIdentifiers.id_icao_ldsSecurityObject));
            final var so = LDSSecurityObject.getInstance(
                    ((ASN1OctetString) eci.getContent()).getOctets()
            );

            final var digestAlgorithm = DigestFactory.getDigest(so.getDigestAlgorithmIdentifier().getAlgorithm().getId());
            System.out.println(digestAlgorithm.getAlgorithmName());

            final var hashes = so.getDatagroupHash();
            for (final var hash : hashes) {
                System.out.println(hash.getDataGroupNumber() + " " + hash.getDataGroupHashValue());
            }
            System.out.println();
        }
    }

    @Test
    // ICAO 9303 Part 10, section 4.6.1 Header and Data Group Presence Information EF.COM
    // Note: this Elementary File's hash is not included in EF.SOD (so not relevant to PA)
    public void testReadCOM() throws Exception {

        try (final var fis = new FileInputStream(System.getProperty("user.home") + "/Documents/passive_auth/efCom");
             final var com = new TLVInputStream(fis)
        ) {
            assertThat(com.readTag(), equalTo(0x60));
            com.readLength();
            try (
                    final var bais = new ByteArrayInputStream(com.readValue());
                    final var elements = new TLVInputStream(bais)) {

                assertThat(elements.readTag(), equalTo(0x5f01));
                elements.readLength();
                final var ldsVersion = elements.readValue();

                assertThat(elements.readTag(), equalTo(0x5f36));
                elements.readLength();
                final var ucVersion = elements.readValue();

                assertThat(elements.readTag(), equalTo(0x5c));
                elements.readLength();
                final var dataGroups = elements.readValue();

                new Formatter(System.out).format(
                        "LDS Version number (aabb)      : %s\n" +
                                "Unicode Version number (aabbcc): %s\n" +
                                "List of all Data Groups present: %s",
                        new String(ldsVersion), new String(ucVersion), Hex.toHexString(dataGroups)
                );
            }
        }
    }

    @Test
    // ICAO 9303 Part 10, section 4.7.1 DATA GROUP 1 — Machine Readable Zone Information
    public void testReadDG1() throws Exception {

        // pre-condition: read from EF.SOD
        final var digestAlgorithmIdentifier = "2.16.840.1.101.3.4.2.1";
        final var hashValue = Hex.decode("7ce3ad4a334529bc7870039d5d5c4d77d9061782181e2c1eabb7e3c18f7cdfaa");

        try (final var fis = new FileInputStream(System.getProperty("user.home") + "/Documents/passive_auth/dg01")) {

            // hash must be equal to hash listed in EF.SOD
            final var contents = fis.readAllBytes();
            final var digestAlgorithm = DigestFactory.getDigest(digestAlgorithmIdentifier);
            digestAlgorithm.update(contents, 0, contents.length);
            final var digest = new byte[digestAlgorithm.getDigestSize()];
            digestAlgorithm.doFinal(digest, 0);
            assertThat(digest, equalTo(hashValue));

            try (final var dg1 = new TLVInputStream(new ByteArrayInputStream(contents))) {

                assertThat(dg1.readTag(), equalTo(0x61));
                dg1.readLength();

                try (final var elements = new TLVInputStream(new ByteArrayInputStream(dg1.readValue()))) {

                    assertThat(elements.readTag(), equalTo(0x5f1f));
                    elements.readLength();
                    System.out.println(new String(elements.readValue()));
                }
            }
        }
    }
}
