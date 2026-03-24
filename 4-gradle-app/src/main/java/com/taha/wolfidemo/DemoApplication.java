package com.taha.wolfidemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Provider;

@SpringBootApplication
@RestController
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @GetMapping("/test-fips")
    public String testFipsConstraint() {
        try {
            // Load BCFIPS provider using Reflection to bypass Maven compilation checks
            if (Security.getProvider("BCFIPS") == null) {
                try {
                    Class<?> providerClass = Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
                    Provider fipsProvider = (Provider) providerClass.getDeclaredConstructor().newInstance();
                    Security.addProvider(fipsProvider);
                } catch (Exception e) {
                    return "CRITICAL ERROR: BCFIPS Provider class not found in classpath.";
                }
            }

            // Attempt to generate an insecure 1024-bit RSA key
            // This operation is forbidden in FIPS Approved Mode
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
            kpg.initialize(1024); 
            kpg.generateKeyPair();
            
            return "FAILURE: System allowed 1024-bit RSA. FIPS policy is not enforced.";
        } catch (Throwable t) {
            String message = t.getMessage();
            String errorType = t.getClass().getSimpleName();
            
            // FipsUnapprovedOperationError or specific FIPS messages indicate success
            if (errorType.contains("FipsUnapprovedOperationError") || 
                (message != null && message.toLowerCase().contains("approved only mode"))) {
                return " just change SUCCESS: FIPS is strictly enforced. System blocked insecure RSA-1024 key generation. Error Type: " + errorType;
            }
            
            return "TERMINATED: An unexpected error occurred: " + errorType + " - " + message;
        }
    }

    @GetMapping("/")
    public String hello() {
        boolean isFipsLoaded = (Security.getProvider("BCFIPS") != null);
        return "Status: RUNNING | FIPS Provider: " + (isFipsLoaded ? "ACTIVE" : "INACTIVE") + " | Test Link: /test-fips";
    }
}