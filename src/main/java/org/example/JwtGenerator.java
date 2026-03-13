package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.jsonwebtoken.Jwts;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

public class JwtGenerator {

    // ANSI Color constants
    public static final String RESET = "\u001B[0m";
    public static final String CYAN = "\u001B[36m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String PURPLE = "\u001B[35m";

    public static void main(String[] args) throws Exception {

        System.out.println(CYAN + "=== Starting JWT Generation ===" + RESET);

        // Load Certificate (supports .cer or .pem)
        X509Certificate cert = loadCertificateFlexible("public_cer.cer");

        // Format certificate issuer with spaces after commas
        String issuerDN = cert.getIssuerX500Principal().getName().replaceAll(",", ", ");

        // Certificate serial number in decimal
        BigInteger serial = cert.getSerialNumber();
        String serialDecimal = serial.toString();

        // Expiration time in seconds from 1970-01-01 UTC
        long expSeconds = cert.getNotAfter().getTime() / 1000;

        System.out.println(GREEN + "[✓] Certificate Loaded" + RESET);
        System.out.println("    Issuer : " + issuerDN);
        System.out.println("    Serial : " + serialDecimal);
        System.out.println("    Expire : " + cert.getNotAfter());

        // Load Private Key (PEM)
        String rawPem = Files.readString(Paths.get("private_key.key"));
        PrivateKey privateKey = getPrivateKeyFromString(rawPem);

        System.out.println(GREEN + "[✓] Private Key Loaded" + RESET);

        // JWT Header like jwt.io
        Map<String, Object> header = Map.of("alg", "RS256");

        // Generate JWT
        String jwt = Jwts.builder()
                .setHeader(header)
                .claim("iss", "BBANKETA")            // member ID issuing the JWT
                .claim("cert_iss", issuerDN)        // formatted certificate issuer
                .claim("cert_sn", serialDecimal)    // serial in decimal
                .claim("exp", expSeconds)           // expiration in seconds
                .claim("jti", UUID.randomUUID().toString()) // unique JWT ID
//                .claim("jti", "1444412412321") // unique JWT ID
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();

        // Beautiful Output
        printBeautifiedJwt(jwt);
    }

    private static void printBeautifiedJwt(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        System.out.println("\n" + YELLOW + "---------------- ENCODED JWT ----------------" + RESET);
        System.out.println(jwt);

        System.out.println("\n" + PURPLE + "---------------- DECODED HEADER ----------------" + RESET);
        Object headerJson = mapper.readValue(Base64.getUrlDecoder().decode(parts[0]), Object.class);
        System.out.println(mapper.writeValueAsString(headerJson));

        System.out.println("\n" + PURPLE + "---------------- DECODED PAYLOAD ----------------" + RESET);
        Object payloadJson = mapper.readValue(Base64.getUrlDecoder().decode(parts[1]), Object.class);
        System.out.println(mapper.writeValueAsString(payloadJson));

        System.out.println("\n" + PURPLE + "---------------- SIGNATURE ----------------" + RESET);
        System.out.println("[Binary Signature Data]");
    }

    // Flexible certificate loader: works with .cer (DER/PEM) or .pem
    private static X509Certificate loadCertificateFlexible(String path) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(path));
        String content = new String(data).trim();

        if (content.contains("-----BEGIN CERTIFICATE-----")) {
            // PEM format: remove headers and decode
            content = content
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            data = Base64.getDecoder().decode(content);
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(data)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bais);
        }
    }

    private static PrivateKey getPrivateKeyFromString(String key) throws Exception {
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyPEM)));
    }
}