package org.example.backend.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;

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
}
