package org.example.backend.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtils {
    //加密密钥
    @Value("${spring.security.jwt.key}")
    String key;
    //令牌时间
    @Value("${spring.security.jwt.expire}")
    int expire;


    //计算过期时间
    public Date expireTime(){
        Calendar calendar = Calendar.getInstance(); //获取实例
        calendar.add(Calendar.HOUR, expire);
        return calendar.getTime();
    }
    //创建jwt
    public String createJwt(UserDetails userDetails, int id, String username){
        //加密算法
        Algorithm algorithm = Algorithm.HMAC256(key);
        //创建
        return JWT.create()
                .withClaim("id", id)
                .withClaim("name", username)
                .withClaim("authorities", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expireTime()) //过期时间
                .withIssuedAt(new Date()) //发牌时间
                .sign(algorithm); //签名
    }
    //解析jwt
    public DecodedJWT resolveJwt(String headerToken){
        String token = convertToken(headerToken);
        if (token == null) return null;
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        try{
            //进行解码
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            Date expiresAt = decodedJWT.getExpiresAt();
            //判断是否过期
            return new Date().after(expiresAt) ? null : decodedJWT;
        }catch (JWTVerificationException e){
            return null;
        }
    }
    //判断Token是否合法，并且获取token令牌
    private String convertToken(String headerToken){
        if(headerToken == null || !headerToken.startsWith("Bearer"))
            return null;
        return headerToken.substring(7);
    }

    //解析为UserDetails
    public UserDetails toUser(DecodedJWT jwt ){
        //取出验证后令牌内的信息
        Map<String, Claim> claimMap = jwt.getClaims();
        return User.withUsername(claimMap.get("name").asString())
                .password("********")
                .authorities(claimMap.get("authorities").asArray(String.class))
                .build();
    }
}
