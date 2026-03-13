package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class JwtVerifier {

    public static void main(String[] args) {

        String token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJCQkFOS0VUQSIsImNlcnRfaXNzIjoiQ049VEVTVCBFVFMgSVBTIElzc3VpbmcgQ0EsIE89RXRoU3dpdGNoLCBDPUVUIiwiY2VydF9zbiI6IjQyMzcxNDE1OTkzMjc0NzI4Mzg3Mjg3NDA5MTkzODAyNTIyMDM0ODA1MTY3OSIsImV4cCI6MTgzNjM3MTMyNywianRpIjoiOTkwNmYyM2EtZmI5MC00MjcyLWJkN2YtY2ViMGY4Y2EwNTI1In0.ap9LX9vY3_vacxqoPoCFdKkHvOe6M0bhuFX9zEV3V2wvp4P7DuzJuOEbMUqBIxOehe5OX2ql3c2-F36ceN-iqNiLkepxBP3mRuaKpIPx9EMoQ0fPuWlXmKko98Wn7jWIXXgGaBuJPM738xtQOkYVqjlVweZv8XcaKgsa82BmRI555NNCBzSMRCY1W6cVr_ILqn5GQnRKr4Zt6VnH7jvBmZf9BaXb4ia2IHbL6rbLm9vNd8omhnFTPECTTLvrkBtQ-BlsiWYyTuB_eFp9gU9Btbi36fffKBRW5-CSCPjq7VDewxVroIdxrz9qDy-Gp56cks4-NkSOLx0QFLtUhobaJw";

        try {

            // Load certificate
            X509Certificate cert = loadCertificateFlexible("public_cer.cer");
            PublicKey publicKey = cert.getPublicKey();

            // Parse JWT
            Jws<Claims> claimsJws = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);

            Claims payload = claimsJws.getPayload();

            System.out.println("\n=== SIGNATURE VALID ===");

            validateClaims(payload, cert);

        } catch (ExpiredJwtException e) {

            System.out.println("\n[!] Token expired but signature is VALID");

            validateClaims(e.getClaims(), loadCertQuiet("public_cer.cer"));

        } catch (Exception e) {

            System.out.println("\n[!] Verification Failed: " + e.getMessage());
        }
    }

    private static void validateClaims(Claims payload, X509Certificate cert) {

        String certIssuer = cert.getIssuerX500Principal().getName().replaceAll(",", ", ");
        String certSerial = cert.getSerialNumber().toString();

        String jwtIssuer = payload.getIssuer();
        String jwtCertIss = payload.get("cert_iss", String.class);
        String jwtCertSn = payload.get("cert_sn", String.class);

        System.out.println("------------------------------------");
        System.out.println("JWT Issuer (iss): " + jwtIssuer);
        System.out.println("JWT Cert Issuer (cert_iss): " + jwtCertIss);
        System.out.println("JWT Cert SN (cert_sn): " + jwtCertSn);
        System.out.println("JWT JTI: " + payload.get("jti"));
        System.out.println("JWT Exp: " + payload.get("exp"));
        System.out.println("------------------------------------");

        // Validate certificate issuer
        if (certIssuer.equals(jwtCertIss)) {
            System.out.println("[✓] cert_iss matches certificate issuer");
        } else {
            System.out.println("[✗] cert_iss mismatch!");
        }

        // Validate certificate serial
        if (certSerial.equals(jwtCertSn)) {
            System.out.println("[✓] cert_sn matches certificate serial");
        } else {
            System.out.println("[✗] cert_sn mismatch!");
        }
    }

    private static X509Certificate loadCertificateFlexible(String path) throws Exception {

        byte[] data = Files.readAllBytes(Paths.get(path));
        String content = new String(data).trim();

        if (content.contains("-----BEGIN CERTIFICATE-----")) {
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

    private static X509Certificate loadCertQuiet(String path) {
        try {
            return loadCertificateFlexible(path);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}