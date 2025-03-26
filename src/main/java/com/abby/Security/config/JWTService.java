package com.abby.Security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JWTService {

    private static final String secretKey = "7uyI9+orzi1Rng5aKoa5lIKxzdA3Xr5/NAhrj+1/NW1iasR24Vl8RMVyM9xC5vt/twB5f6kauOAdhqVG5lhzscRfFcdvyluDv+F8PuK7Jf+4wlR0h9YRv96BAP9KqmBJvgNK5LlrFO9l86Bzmh22nA99+pA15MMZucSrrAgilO6ZRgYyJTBeDcrAEZ3J+6OkcLxbC8sGox4wZEvWwUAoLGxHKHcehh0y00VbGDT33/8zCXjOIXAvfRn02PSxo7QhELZJ2TNjP+dcXbOuvE3MR3nLCONVzPJXIZusCuaRews7+RWQkT0I0uYJZjZFXw6C1Tg2AbCglM6Obes4iN4lrs561ZNw4+Cqag/QUfGXTm8=\n";
    public String extractUserName(String token) {
        //JWT - Header, Payload, Verify Signature
        // Header - type of token , signing algorithm
        // Payload - claims (details of user) registered, private, public
        // jwt.io
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    private Claims  extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //signing key - digitally signed jwt used to verify sender of jwt is who he
    // claims to be and msg has not been changed on the way
    private Key getSigningKey() {
        byte[] keyByte = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyByte);
    }

    //generate Token
    public String generateToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date((System.currentTimeMillis())))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public String generateToken(UserDetails userDetails){
           return generateToken(new HashMap<>(),userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUserName(token);
        return (username).equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}
