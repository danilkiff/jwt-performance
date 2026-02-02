package com.github.danilkiff.jwt.perf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.Signature;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JwtFilterTest {

    private JwtFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        filter = filter("default");
    }

    @ParameterizedTest(name = "accepts valid {0}")
    @MethodSource("validTokens")
    void acceptsValidTokens(String algorithm, String token) {
        var outcome = invokeWithBearer(token);

        assertThat(outcome.chainCalled())
                .as("%s token should pass to the next gateway filter", algorithm)
                .isTrue();
        assertThat(outcome.status()).isNull();
    }

    @ParameterizedTest(name = "rejects tampered {0}")
    @MethodSource("tamperedTokens")
    void rejectsTamperedTokens(String algorithm, String token) {
        var outcome = invokeWithBearer(token);

        assertUnauthorized(outcome, algorithm + " token with changed protected data");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "not-a-token",
            "Bearer",
            "header.payload.signature.extra"
    })
    void rejectsMalformedBearerTokens(String token) {
        var outcome = invokeWithBearer(token);

        assertUnauthorized(outcome, "malformed bearer token");
    }

    @Test
    void rejectsMissingAuthorizationHeader() {
        var outcome = invoke(null);

        assertUnauthorized(outcome, "missing Authorization header");
    }

    @Test
    void rejectsNonBearerAuthorizationHeader() {
        var outcome = invoke("Basic " + token("hs256"));

        assertUnauthorized(outcome, "non-Bearer Authorization header");
    }

    @Test
    void rejectsUnsupportedJwsAlgorithmBeforeRouting() {
        var outcome = invokeWithBearer(unsupportedJwsToken());

        assertUnauthorized(outcome, "unsupported JWS alg");
    }

    @Test
    void acceptsEdDsaThroughJcaVerifier() throws Exception {
        filter = filter("bc");

        var outcome = invokeWithBearer(token("eddsa"));

        assertThat(outcome.chainCalled()).isTrue();
        assertThat(outcome.status()).isNull();
    }

    @Test
    void rejectsTamperedEdDsaThroughJcaVerifier() throws Exception {
        filter = filter("bc");

        var outcome = invokeWithBearer(tamperJwsPayload(token("eddsa")));

        assertUnauthorized(outcome, "tampered EdDSA token through JCA verifier");
    }

    @Test
    void acceptsEdDsaServicedByBouncyCastleProvider() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        try {
            assertThat(Signature.getInstance("Ed25519").getProvider().getName())
                    .as("BC should service Ed25519 once installed at priority 1")
                    .isEqualTo("BC");

            filter = filter("bc");

            var outcome = invokeWithBearer(token("eddsa"));

            assertThat(outcome.chainCalled()).isTrue();
            assertThat(outcome.status()).isNull();
        } finally {
            Security.removeProvider("BC");
        }
    }

    @Test
    void rejectsAlgNoneToken() {
        var outcome = invokeWithBearer(algNoneToken());

        assertUnauthorized(outcome, "alg=none is never acceptable");
    }

    static Stream<Arguments> validTokens() {
        return Stream.of(
                arguments("HS256", token("hs256")),
                arguments("RS256", token("rs256")),
                arguments("ES256", token("es256")),
                arguments("EdDSA", token("eddsa")),
                arguments("JWE", token("jwe"))
        );
    }

    static Stream<Arguments> tamperedTokens() {
        return Stream.of(
                arguments("HS256", tamperJwsPayload(token("hs256"))),
                arguments("RS256", tamperJwsPayload(token("rs256"))),
                arguments("ES256", tamperJwsPayload(token("es256"))),
                arguments("EdDSA", tamperJwsPayload(token("eddsa"))),
                arguments("JWE", tamperJweCiphertext(token("jwe")))
        );
    }

    private static JwtFilter filter(String cryptoProvider) throws Exception {
        return new JwtFilter(
                new ClassPathResource("secrets-dev/hs256-secret.txt"),
                new ClassPathResource("secrets-dev/rs256-public.pem"),
                new ClassPathResource("secrets-dev/es256-public.pem"),
                new ClassPathResource("secrets-dev/eddsa-public.pem"),
                new ClassPathResource("secrets-dev/rsa-private.pem"),
                cryptoProvider
        );
    }

    private Outcome invokeWithBearer(String token) {
        return invoke("Bearer " + token);
    }

    private Outcome invoke(String authorization) {
        var request = MockServerHttpRequest.get("/api/ping");
        if (authorization != null) {
            request.header(HttpHeaders.AUTHORIZATION, authorization);
        }

        var exchange = MockServerWebExchange.from(request);
        var chainCalled = new AtomicBoolean(false);

        filter.filter(exchange, serverWebExchange -> {
            chainCalled.set(true);
            return Mono.empty();
        }).block();

        return new Outcome(exchange.getResponse().getStatusCode(), chainCalled.get());
    }

    private static void assertUnauthorized(Outcome outcome, String caseName) {
        assertThat(outcome.chainCalled())
                .as("%s must not reach the downstream chain", caseName)
                .isFalse();
        assertThat(outcome.status()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private static String token(String name) {
        try {
            return new ClassPathResource("tokens/" + name + ".txt")
                    .getContentAsString(StandardCharsets.UTF_8)
                    .trim();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to read token fixture: " + name, e);
        }
    }

    private static String tamperJwsPayload(String token) {
        String[] parts = token.split("\\.", -1);
        assertThat(parts).hasSize(3);
        parts[1] = flipLastBase64UrlChar(parts[1]);
        return String.join(".", parts);
    }

    private static String tamperJweCiphertext(String token) {
        String[] parts = token.split("\\.", -1);
        assertThat(parts).hasSize(5);
        parts[3] = flipLastBase64UrlChar(parts[3]);
        return String.join(".", parts);
    }

    private static String flipLastBase64UrlChar(String value) {
        assertThat(value).isNotEmpty();
        char replacement = value.charAt(value.length() - 1) == 'A' ? 'B' : 'A';
        return value.substring(0, value.length() - 1) + replacement;
    }

    private static String unsupportedJwsToken() {
        return craftJws("{\"alg\":\"PS256\"}", "{\"sub\":\"unsupported\"}", "unused-signature");
    }

    private static String algNoneToken() {
        // Classic "alg: none" attack: header claims no signature and the third segment
        // is empty — Nimbus will parse it, our filter's switch must reject.
        return craftJws("{\"alg\":\"none\"}", "{\"sub\":\"attacker\"}", "");
    }

    private static String craftJws(String headerJson, String payloadJson, String signatureBytes) {
        var encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signature = encoder.encodeToString(signatureBytes.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + signature;
    }

    private record Outcome(HttpStatusCode status, boolean chainCalled) {
    }
}
