package com.example.jwt.authentication.JWT.authentication.utils;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.function.Function;

@Component
public class JwtUtil {

    private final ResourceLoader resourceLoader;

    private PrivateKey privateKey;

    private PublicKey publicKey;

    @Value("${jwt.expirationAt}")
    private int expirationAt;

    @Value("${jwt.privateKeyPath}")
    private String privateKeyPath;

    @Value("${jwt.publicKeyPath}")
    private String publicKeyPath;

    public JwtUtil(ResourceLoader resourceLoader) {

        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() throws Exception {

        this.privateKey = this.loadPrivateKey(this.privateKeyPath);
        this.publicKey = this.loadPublicKey(this.publicKeyPath);
    }

    private Claims getAllClaimsFromToken(String token) {

        return Jwts.parser()
                .setSigningKey(this.publicKey)
                .parseClaimsJws(token)
                .getBody();
    }

    private PrivateKey loadPrivateKey(String filePath) throws Exception {

        Resource resource = resourceLoader.getResource(filePath);
        byte[] keyBytes = Files.readAllBytes(resource.getFile().toPath());
        String privateKeyPEM = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String filePath) throws Exception {

        Resource resource = resourceLoader.getResource(filePath);
        byte[] keyBytes = Files.readAllBytes(resource.getFile().toPath());
        String publicKeyPEM = new String(keyBytes)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {

        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    public Date getExpirationDateFromToken(String token) {

        return this.getClaimFromToken(token, Claims::getExpiration);
    }

    private Boolean isTokenExpired(String token) {

        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + this.expirationAt * 1000L))
                .signWith(SignatureAlgorithm.RS256, this.privateKey)
                .compact();
    }

    public String generateToken(UUID userId) {

        Map<String, Object> claims = new HashMap<>();
        return this.doGenerateToken(claims, userId.toString());
    }

    public UUID getUserId(String token) {

        return UUID.fromString(
                this.getClaimFromToken(token, Claims::getSubject)
        );
    }

    public Boolean validateToken(String token) {

        return !this.isTokenExpired(token);
    }

}
