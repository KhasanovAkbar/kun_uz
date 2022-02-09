package g46.kun.uz.util;

import com.google.gson.Gson;
import g46.kun.uz.dto.UserDetails;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;

import java.util.Date;

public class TokenProcess {

    private final static String secretKey = "kalit";

    public static String generateJwt(Integer id) {

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setId("some Id");
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.setSubject(String.valueOf(id));
        jwtBuilder.signWith(SignatureAlgorithm.HS256, secretKey);
        jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + (60 * 60 * 1000)));
        jwtBuilder.setIssuer("kun.uz");

        String jwt = jwtBuilder.compact();
        return jwt;
    }

    public static String generateJwt(UserDetails userDetails) {

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setId("some Id");
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.setSubject(new Gson().toJson(userDetails));
        jwtBuilder.signWith(SignatureAlgorithm.HS256, secretKey);
        jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + (60 * 60 * 1000)));
        jwtBuilder.setIssuer("kun.uz");

        String jwt = jwtBuilder.compact();
        return jwt;
    }

    public static Integer encodeJwt(String jwt) {
        JwtParser jwtParser = Jwts.parser();

        jwtParser.setSigningKey(secretKey);
        Jws jws = jwtParser.parseClaimsJws(jwt);

        Claims claims = (Claims) jws.getBody();
        String id = claims.getSubject();

        return Integer.parseInt(id);
    }

    public static UserDetails encodeJwtJson(String jwt) {
        JwtParser jwtParser = Jwts.parser();

        jwtParser.setSigningKey(secretKey);
        Jws jws = jwtParser.parseClaimsJws(jwt);

        Claims claims = (Claims) jws.getBody();
        String json = claims.getSubject(); // GET ID

        return new Gson().fromJson(json, UserDetails.class);
    }

    //        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary("kalit");
//        Key signingKey = new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.toString());


}
