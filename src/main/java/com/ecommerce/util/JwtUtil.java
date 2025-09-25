package com.ecommerce.util;

import com.ecommerce.model.entity.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @Value("${app.jwt.access-token-expiration}")
    private long accessTokenExpiration;
    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public JwtUtil(@Value("${PRIVATE_KEY}") String privateKetStr,
                   @Value("${PUBLIC_KEY}") String publicKetStr) throws Exception {
        // Load private key
        // ClassPathResource privateKeyResource = new ClassPathResource("keys/private.pem");
        // String privateKeyString = new String(privateKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        this.privateKey = parsePrivateKey(privateKetStr);

        // Load public key
        // ClassPathResource publicKeyResource = new ClassPathResource("keys/public.pem");
        // String publicKeyString = new String(publicKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        this.publicKey = parsePublicKey(publicKetStr);
    }

    private PrivateKey parsePrivateKey(String keyString) throws Exception {
        String privateKeyPEM = keyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey parsePublicKey(String keyString) throws Exception {
        String publicKeyPEM = keyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public String generateAccessToken(User user) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .claim("role", user.getRole().name())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claims
        );
        signedJWT.sign(new RSASSASigner(privateKey));
        return signedJWT.serialize();
    }

    public String generateRefreshToken(User user) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claims
        );
        signedJWT.sign(new RSASSASigner(privateKey));
        return signedJWT.serialize();
    }

    public boolean validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            return signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public String getEmailFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            if (signedJWT.verify(verifier)) {
                return signedJWT.getJWTClaimsSet().getSubject();
            }
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
        return null;
    }
}