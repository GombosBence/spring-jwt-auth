package com.secuirty;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    private final Key key;

    public JwtService(@Value("${certificate.path}") String path, @Value("${certificate.password}") char[] password,
                      @Value("${certificate.alias}") String alias)
            throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        this.key = getKey(path, password, alias);
    }

    private static Key getKey(String path, char[] password, String alias) throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(path), password);
        return keyStore.getKey(alias, password);
    }

    private String createToken(String email){
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))// 1 hour expiration
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String token, UserDetails userDetails){
        return extractUsername(token).equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean isTokenExpired(String token){
        return new Date().after(extractExpiration(token));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        return claimsResolver.apply(extractAllClaims(token));
    }

    public Claims extractAllClaims(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
