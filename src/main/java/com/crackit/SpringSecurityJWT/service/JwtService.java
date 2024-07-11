package com.crackit.SpringSecurityJWT.service;

import com.crackit.SpringSecurityJWT.constant.AppConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${secret.jwt.secret-key}")
    private String SECRET;

    public String extractUserName(String jwtToken) {
        String userName = extractClaims(jwtToken, Claims::getSubject);
        System.out.println("Extracting username from token: " + userName);
        return extractClaims(jwtToken, Claims::getSubject);
    }

    public <T> T extractClaims(String jwtToken, Function<Claims, T> claimResolver){
        Claims claims = extractAllClaims(jwtToken);
        return claimResolver.apply(claims);
    }

    public Claims extractAllClaims(String jwtToken) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails){
        System.out.println("Generating token");
        return generateToken(new HashMap<>(), userDetails);
    }
    public Boolean isTokenValid(
            String jwtToken,
            UserDetails userDetails) {
        String username = extractUserName(jwtToken);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken);
    }

    public Boolean isTokenValidOrNot(
            String jwtToken,
            String userName) {
        String username = extractUserName(jwtToken);
        return username.equals(userName) && !isTokenExpired(jwtToken);
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaims(jwtToken, Claims::getExpiration);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails )
    {
        System.out.println("Generating token in second method");
        System.out.println("User details: "+userDetails.getUsername());
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + AppConstants.JWT_EXPIRATION)) // 1000 * 60 means 1 minute time for token to expire
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
