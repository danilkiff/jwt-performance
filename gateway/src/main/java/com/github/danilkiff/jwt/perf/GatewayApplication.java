package com.github.danilkiff.jwt.perf;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import javax.crypto.Cipher;

@SpringBootApplication
public class GatewayApplication {

    private static final Logger log = LoggerFactory.getLogger(GatewayApplication.class);

    public static void main(String[] args) {
        configureCryptoProvider();
        SpringApplication.run(GatewayApplication.class, args);
    }

    private static void configureCryptoProvider() {
        String mode = System.getenv().getOrDefault("CRYPTO_PROVIDER", "default").toLowerCase();
        switch (mode) {
            case "bc" -> {
                Security.insertProviderAt(new BouncyCastleProvider(), 1);
                log.info("[crypto] BouncyCastle installed as highest-priority JCE provider");
            }
            case "accp" -> {
                AmazonCorrettoCryptoProvider.install();
                AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
                log.info("[crypto] Amazon Corretto Crypto Provider installed (AWS-LC native)");
            }
            default -> log.info("[crypto] Using default JDK JCE providers");
        }
        logProvider("SHA256withRSA");
        logProvider("SHA256withECDSA");
        logProvider("Ed25519");
        logCipherProvider("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        logCipherProvider("AES/GCM/NoPadding");
    }

    private static void logProvider(String algorithm) {
        try {
            Provider p = Signature.getInstance(algorithm).getProvider();
            log.info("[crypto]   {} -> {} ({})", algorithm, p.getName(), p.getVersionStr());
        } catch (Exception e) {
            log.info("[crypto]   {} -> unavailable ({})", algorithm, e.getClass().getSimpleName());
        }
    }

    private static void logCipherProvider(String transform) {
        try {
            Provider p = Cipher.getInstance(transform).getProvider();
            log.info("[crypto]   {} -> {} ({})", transform, p.getName(), p.getVersionStr());
        } catch (Exception e) {
            log.info("[crypto]   {} -> unavailable ({})", transform, e.getClass().getSimpleName());
        }
    }
}
