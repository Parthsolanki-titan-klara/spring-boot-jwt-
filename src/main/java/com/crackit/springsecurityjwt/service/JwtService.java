package com.crackit.springsecurityjwt.service;

import com.crackit.springsecurityjwt.user.User;
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

    public String generateToken(User user){
        return generateToken(new HashMap<>(), user);
    }

    public String generateRefreshToken(User user){
        return generateRefreshToken(new HashMap<>(), user);
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
            Map<String, String> extraClaims,
            User user )
    {
        System.out.println("Generating token..........");
        String userName = user.getFirstName() + " " + user.getLastName();
        extraClaims.put("userName", userName );
        extraClaims.put("role",user.getUserRole().toString());
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 2))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(
            Map<String, String> extraClaims,
            User user )
    {
        System.out.println("Generating Refresh token..............");
        String userName = user.getFirstName() + " " + user.getLastName();
        extraClaims.put("userName", userName );
        extraClaims.put("role",user.getUserRole().toString());
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 5))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

}
