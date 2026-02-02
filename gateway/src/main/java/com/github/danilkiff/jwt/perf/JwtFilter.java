package com.github.danilkiff.jwt.perf;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;

@Component
public class JwtFilter {

    private final byte[] hs256Secret;
    private final RSAKey rsaPublicKey;
    private final ECKey ecPublicKey;
    private final OctetKeyPair edPublicKey;
    private final RSAKey jwePrivateKey;

    public JwtFilter(
            @Value("${HS256_SECRET_FILE}") Resource hsSecret,
            @Value("${RS256_PUBLIC_KEY}") Resource rsaPub,
            @Value("${ES256_PUBLIC_KEY}") Resource ecPub,
            @Value("${EDDSA_PUBLIC_KEY}") Resource edPub,
            @Value("${JWE_PRIVATE_KEY}") Resource jwePriv
    ) throws Exception {
        this.hs256Secret = hsSecret.getContentAsByteArray();
        this.rsaPublicKey = (RSAKey) RSAKey.parseFromPEMEncodedObjects(read(rsaPub));
        this.ecPublicKey = (ECKey) ECKey.parseFromPEMEncodedObjects(read(ecPub));
        this.edPublicKey = parseEd25519PublicKey(read(edPub));
        this.jwePrivateKey = (RSAKey) RSAKey.parseFromPEMEncodedObjects(read(jwePriv));
    }

    private static String read(Resource resource) {
        try {
            return resource.getContentAsString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Nimbus 10.x OctetKeyPair.parseFromPEMEncodedObjects does not accept
    // Ed25519 SPKI PEMs, so extract the raw 32-byte public key via BC.
    private static OctetKeyPair parseEd25519PublicKey(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo) parser.readObject();
            byte[] raw = spki.getPublicKeyData().getBytes();
            return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(raw)).build();
        }
    }

    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        var auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null || !auth.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        var token = auth.substring("Bearer ".length());

        try {
            if (token.split("\\.").length == 3) {
                verifyJws(token);
            } else {
                verifyJwe(token);
            }
        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private void verifyJws(String token) throws Exception {
        var jwt = SignedJWT.parse(token);
        var alg = jwt.getHeader().getAlgorithm().getName();

        switch (alg) {
            case "HS256" -> jwt.verify(new MACVerifier(hs256Secret));
            case "RS256" -> jwt.verify(new RSASSAVerifier(rsaPublicKey));
            case "ES256" -> jwt.verify(new ECDSAVerifier(ecPublicKey));
            case "EdDSA" -> jwt.verify(new Ed25519Verifier(edPublicKey));
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        }
    }

    private void verifyJwe(String token) throws Exception {
        var jwe = JWEObject.parse(token);
        jwe.decrypt(new RSADecrypter(jwePrivateKey));
    }
}
