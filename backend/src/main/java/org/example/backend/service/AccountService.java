package org.example.backend.service;

import com.baomidou.mybatisplus.extension.service.IService;
import org.example.backend.entity.dto.Account;
import org.example.backend.entity.vo.request.ConfirmResetVO;
import org.example.backend.entity.vo.request.EmailRegisterVO;
import org.example.backend.entity.vo.request.PasswordResetVO;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AccountService extends IService<Account> , UserDetailsService {
    Account findAccountByUsernameOrEmail(String text);

    //注册邮件验证码
    String registerEmailVerifyCode(String type, String email, String ip);
    //注册
    String registerEmailAccount(EmailRegisterVO emailRegisterVO);
    String resetConfirm(ConfirmResetVO confirmResetVO);
    String resetEmailPassword(PasswordResetVO passwordResetVO);
}
