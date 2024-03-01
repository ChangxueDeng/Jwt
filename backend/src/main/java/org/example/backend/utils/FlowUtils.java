package org.example.backend.utils;

import jakarta.annotation.Resource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class FlowUtils {
    @Resource
    StringRedisTemplate stringRedisTemplate;
    public boolean limitOnceCheck(String key, int coldTime){
        if(Boolean.TRUE.equals(stringRedisTemplate.hasKey(key))){
            //正在冷却
            return false;
        }else {
            //进行冷却
            stringRedisTemplate.opsForValue().set(key, "", coldTime, TimeUnit.SECONDS);
        }
        return true;
    }
}
