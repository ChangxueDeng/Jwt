package org.example.backend.service;

import com.baomidou.mybatisplus.extension.service.IService;
import org.example.backend.entity.dto.Account;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

public interface AccountService extends IService<Account> , UserDetailsService {
    Account findAccountByUsernameOrEmail(String text);
}
