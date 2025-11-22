package com.github.danilkiff.jwt.perf;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class JwtFilter {

    private final byte[] hs256Secret;
    private final RSAKey rsaPublicKey;
    private final ECKey ecPublicKey;
    private final RSAKey jwePrivateKey;

    public JwtFilter(
            @Value("${HS256_SECRET_FILE}") Resource hsSecret,
            @Value("${RS256_PUBLIC_KEY}") Resource rsaPub,
            @Value("${ES256_PUBLIC_KEY}") Resource ecPub,
            @Value("${JWE_PRIVATE_KEY}") Resource jwePriv
    ) throws Exception {
        this.hs256Secret = hsSecret.getContentAsByteArray();
        this.rsaPublicKey = (RSAKey) RSAKey.parseFromPEMEncodedObjects(read(rsaPub));
        this.ecPublicKey = (ECKey) ECKey.parseFromPEMEncodedObjects(read(ecPub));
        this.jwePrivateKey = (RSAKey) RSAKey.parseFromPEMEncodedObjects(read(jwePriv));
    }

    private static String read(Resource resource) {
        try {
            return resource.getContentAsString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
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
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        }
    }

    private void verifyJwe(String token) throws Exception {
        var jwe = JWEObject.parse(token);
        jwe.decrypt(new RSADecrypter(jwePrivateKey));
    }
}
