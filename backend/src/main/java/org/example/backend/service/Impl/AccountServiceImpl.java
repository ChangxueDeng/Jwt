package org.example.backend.service.Impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import jakarta.annotation.Resource;
import org.example.backend.entity.dto.Account;
import org.example.backend.entity.vo.request.ConfirmResetVO;
import org.example.backend.entity.vo.request.EmailRegisterVO;
import org.example.backend.entity.vo.request.PasswordResetVO;
import org.example.backend.mapper.AccountMapper;
import org.example.backend.service.AccountService;
import org.example.backend.utils.Const;
import org.example.backend.utils.FlowUtils;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;


@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {
    @Resource
    FlowUtils flowUtils;
    @Resource
    AmqpTemplate amqpTemplate;
    @Resource
    StringRedisTemplate stringRedisTemplate;

    @Resource
    PasswordEncoder passwordEncoder;
    public Account findAccountByUsernameOrEmail(String text){
        return this.query()
                .eq("username", text)
                .or()
                .eq("email", text)
                .one();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = this.findAccountByUsernameOrEmail(username);
        if (account == null){
            throw  new UsernameNotFoundException("用户名或密码错误");
        }
        return User.withUsername(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    //邮件发送

    @Override
    public String registerEmailVerifyCode(String type, String email, String ip) {
        //加锁防止多次调用
        synchronized (ip.intern()){
            if(!this.verifyLimit(ip)){
                return "请求频繁，请稍后再试";
            }
            //生成验证码
            Random random = new Random();
            int code = random.nextInt(900000) + 100000;

            //用于存入消息队列
            Map<String, Object> data = Map.of("type", type, "email", email, "code", code);
            amqpTemplate.convertAndSend("email", data);
            //验证码存入redis,用于之后验证
            stringRedisTemplate.opsForValue().set(Const.VERIFY_EMAIL_DATA + email, String.valueOf(code), 3, TimeUnit.MINUTES);
            return null;
        }

    }
    //进行限流
    private boolean verifyLimit(String ip){
        String key = Const.VERIFY_EMAIL_LIMIT + ip;
        return flowUtils.limitOnceCheck(key, 60);
    }
    //注册

    @Override
    public String registerEmailAccount(EmailRegisterVO emailRegisterVO) {
        String username = emailRegisterVO.getUsername();
        String email = emailRegisterVO.getEmail();
        String code = stringRedisTemplate.opsForValue().get(Const.VERIFY_EMAIL_DATA + email);
        if(code == null) return "请先获取验证码";
        if(!code.equals(emailRegisterVO.getCode())) return "验证码错误，请重新输入";
        if(existsAccountByEmail(email)) return "此电子邮件已被其他用户注册";
        if(existsAccountByUsername(username)) return "此用户已存在";
        String password = passwordEncoder.encode(emailRegisterVO.getPassword());
        Account account = new Account(null, username, password, email, "user", new Date());
        if(this.save(account)){
            //删除验证码
            stringRedisTemplate.delete(Const.VERIFY_EMAIL_DATA + email);
            return null;
        }else {
            return "内部错误，请联系管理员";
        }

    }
    private boolean existsAccountByEmail(String email){
        //return this.exists(Wrappers.<Account>query().eq("email", email));
        return this.baseMapper.exists(Wrappers.<Account>query().eq("email", email));
    }
    private boolean existsAccountByUsername(String username){
        return this.baseMapper.exists(Wrappers.<Account>query().eq("username", username));
    }

    @Override
    public String resetConfirm(ConfirmResetVO confirmResetVO) {
        String email = confirmResetVO.getEmail();
        String code = stringRedisTemplate.opsForValue().get(Const.VERIFY_EMAIL_DATA + email);
        if(code == null) return "请先获取验证码";
        if(!code.equals(confirmResetVO.getCode())) return "验证码错误，请重新输入";
        return null;
    }

    @Override
    public String resetEmailPassword(PasswordResetVO passwordResetVO) {
        String email = passwordResetVO.getEmail();
        String verify = this.resetConfirm(new ConfirmResetVO(email, passwordResetVO.getCode()));
        if(verify != null) return verify;
        String password = passwordEncoder.encode(passwordResetVO.getPassword());
        boolean update = this.update().eq("email", email).set("password", password).update();
        if(update){
            stringRedisTemplate.delete(Const.VERIFY_EMAIL_DATA + email);
        }
        return null;
    }
}
