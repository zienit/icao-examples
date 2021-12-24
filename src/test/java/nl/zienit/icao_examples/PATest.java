package nl.zienit.icao_examples;

import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.util.Formatter;
import java.util.Set;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;

// Resources used are published by BSI at the following url:
// https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip
// note: there are some differences between BER-TLV, as defined in ISO/IEC 7816
// for SmartCards, and BER as defined in X.690. In version 1.70 of BC, these differences
// lead to an exception being thrown when parsing Ef.COM. For this reason, two different
// libraries are used. See also this discussion: https://github.com/bcgit/bc-java/issues/1081
public class PATest {

    // ICAO 9303 part 11, section 9.2.3 PACE Object Identifier
    static final ASN1ObjectIdentifier id_PACE = BSIObjectIdentifiers.bsi_de.branch("2.2.4");
    static final ASN1ObjectIdentifier id_PACE_DH_GM = id_PACE.branch("1");
    static final ASN1ObjectIdentifier id_PACE_DH_IM = id_PACE.branch("3");
    static final ASN1ObjectIdentifier id_PACE_ECDH_GM = id_PACE.branch("2");
    static final ASN1ObjectIdentifier id_PACE_ECDH_IM = id_PACE.branch("4");
    static final ASN1ObjectIdentifier id_PACE_ECDH_CAM = id_PACE.branch("6");

    // ICAO 9303 part 11, section 9.2.7 Chip Authentication Object Identifier
    static final ASN1ObjectIdentifier id_CA = BSIObjectIdentifiers.bsi_de.branch("2.2.3");
    static final ASN1ObjectIdentifier id_PK = BSIObjectIdentifiers.bsi_de.branch("2.2.1");

    // ICAO 9303 part 11, section 9.2.9 Terminal Authentication Object Identifiers
    static final ASN1ObjectIdentifier id_TA = BSIObjectIdentifiers.bsi_de.branch("2.2.2");

    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    // ICAO 9303 Part 10, section 4.6.2 Document Security Object EF.SOD
    public void testReadSOD() throws Exception {
        try (final var fis = getClass().getClassLoader().getResourceAsStream("EF_SOD.bin");
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

            // note: validation of the Document Signer certificate itself against CSCA cert and CRL is skipped
            // in this test, but MUST be done in production applications!

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

        try (final var fis = getClass().getClassLoader().getResourceAsStream("EF_COM.bin");
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
                                "List of all Data Groups present: %s\n",
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
        final var hashValue = Hex.decode("4170ca879fce6a22ffef1567ff88079f415c66ead250ab5f23781ac2cdbf42b6");

        try (final var fis = getClass().getClassLoader().getResourceAsStream("Datagroup1.bin")) {

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

    // ICAO 9303 Part 10, section 4.7.14 DATA GROUP 14 — Security Options
    @Test
    public void testReadDG14() throws Exception {

        // pre-condition: read from EF.SOD
        final var digestAlgorithmIdentifier = "2.16.840.1.101.3.4.2.1";
        final var hashValue = Hex.decode("cf5004ffccd64e1a8bd3a42fd53814ec3d4481640be1906d0ecfeb016ef6a6ae");

        try (final var fis = getClass().getClassLoader().getResourceAsStream("Datagroup14.bin")) {

            // hash must be equal to hash listed in EF.SOD
            final var contents = fis.readAllBytes();
            final var digestAlgorithm = DigestFactory.getDigest(digestAlgorithmIdentifier);
            digestAlgorithm.update(contents, 0, contents.length);
            final var digest = new byte[digestAlgorithm.getDigestSize()];
            digestAlgorithm.doFinal(digest, 0);
            assertThat(digest, equalTo(hashValue));

            try (final var dg14 = new TLVInputStream(new ByteArrayInputStream(contents))) {

                assertThat(dg14.readTag(), equalTo(0x6E));
                dg14.readLength();
                final var securityInfos = ASN1Set.getInstance(dg14.readValue());

                final var out = new Formatter(System.out);

                for (final var securityInfo : securityInfos.toArray()) {

                    final var i = ((ASN1Sequence) securityInfo).iterator();
                    final var protocol = (ASN1ObjectIdentifier) i.next();

                    if (protocol.on(id_PACE)) {

                        if (Set.of(id_PACE_DH_GM, id_PACE_DH_IM, id_PACE_ECDH_GM, id_PACE_ECDH_IM, id_PACE_ECDH_CAM).contains(protocol)) {
                            // ICAO 9303 Part 11, section 9.2.2 PACEDomainParameterInfo
                            final var domainParameter = AlgorithmIdentifier.getInstance(i.next());
                            final var parameterId = i.hasNext() ? ((ASN1Integer) i.next()).getValue() : null;
                            out.format("PACEDomainParameterInfo %s %d", domainParameter.getAlgorithm(), parameterId);

                        } else {
                            // ICAO 9303 Part 11, section 9.2.1 PACEInfo
                            final var version = ((ASN1Integer) i.next()).getValue();
                            final var parameterId = (i.hasNext()) ? ((ASN1Integer) i.next()).getValue() : null;
                            out.format("PACEInfo %s %d %d\n", protocol, version, parameterId);
                        }

                    } else if (protocol.equals(ICAOObjectIdentifiers.id_icao_aaProtocolObject)) {
                        // ICAO 9303 Part 11, section 9.2.4 ActiveAuthenticationInfo
                        final var version = ((ASN1Integer) i.next()).getValue();
                        final var signatureAlgorithm = (ASN1ObjectIdentifier) i.next();
                        out.format("ActiveAuthenticationInfo %d %s\n", version, signatureAlgorithm);

                    } else if (protocol.on(id_CA)) {
                        // ICAO 9303 Part 11, section 9.2.5 ChipAuthenticationInfo
                        final var version = ((ASN1Integer) i.next()).getValue();
                        final var keyId = (i.hasNext()) ? ((ASN1Integer) i.next()).getValue() : null;
                        out.format("ChipAuthenticationInfo %d %d\n", version, keyId);

                    } else if (protocol.on(id_PK)) {
                        // ICAO 9303 Part 11, section 9.2.6 ChipAuthenticationPublicKeyInfo
                        final var chipAuthenticationPublicKey = SubjectPublicKeyInfo.getInstance(i.next());
                        final var keyId = (i.hasNext()) ? ((ASN1Integer) i.next()).getValue() : null;
                        out.format("ChipAuthenticationPublicKeyInfo %s %.40s... %d\n",
                                chipAuthenticationPublicKey.getAlgorithm().getAlgorithm(),
                                chipAuthenticationPublicKey.getPublicKeyData(),
                                keyId);

                    } else if (protocol.equals(id_TA)) {
                        // ICAO 9303 part 11, section 9.2.8 TerminalAuthenticationInfo
                        final var version = ((ASN1Integer) i.next()).getValue();
                        out.format("TerminalAuthenticationInfo %d\n", version);
                    }
                    // ICAO 9303 part 11, section 9.2: SecurityInfos MAY contain additional entries indicating support for
                    // other protocols or providing other information. The inspection system MAY discard any unknown entry.
                }
            }
        }
    }

    // ICAO 9303 Part 10, section 4.7.15 DATA GROUP 15 — Active Authentication Public Key Info
    @Test
    public void testReadDG15() throws Exception {

        try (final var fis = getClass().getClassLoader().getResourceAsStream("Datagroup15.bin");
             final var dg15 = new TLVInputStream(fis)) {

            assertThat(dg15.readTag(), equalTo(0x6F));
            dg15.readLength();

            final var activeAuthenticationPublicKey = SubjectPublicKeyInfo.getInstance(dg15.readValue());
            new Formatter(System.out).format("ActiveAuthenticationPublicKey %s %.40s...\n",
                    activeAuthenticationPublicKey.getAlgorithm().getAlgorithm(),
                    activeAuthenticationPublicKey.getPublicKeyData()
            );

            // Exception is thrown if BC does not support this algorithm
            new JcaContentVerifierProviderBuilder().setProvider("BC").build(activeAuthenticationPublicKey);
        }
    }
}
