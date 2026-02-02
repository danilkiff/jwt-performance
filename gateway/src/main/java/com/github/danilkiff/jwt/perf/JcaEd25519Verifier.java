package com.github.danilkiff.jwt.perf;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.EdDSAProvider;
import com.nimbusds.jose.util.Base64URL;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

// Verifies EdDSA (Ed25519) JWS via the standard JCA API so the currently
// installed JCE provider (Conscrypt / SunEC / ...) services the scalar mult,
// instead of Tink as Nimbus's own Ed25519Verifier hard-codes.
public final class JcaEd25519Verifier extends EdDSAProvider implements JWSVerifier {

    private final PublicKey publicKey;

    public JcaEd25519Verifier(PublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signedContent, Base64URL signature) throws JOSEException {
        if (!JWSAlgorithm.EdDSA.equals(header.getAlgorithm())) {
            throw new JOSEException("Expected alg=EdDSA, got " + header.getAlgorithm());
        }
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(signedContent);
            return sig.verify(signature.decode());
        } catch (GeneralSecurityException e) {
            throw new JOSEException("Ed25519 verification failed: " + e.getMessage(), e);
        }
    }
}
