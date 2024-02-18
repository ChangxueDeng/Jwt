package org.example.backend.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.example.backend.entity.dto.Account;
import org.example.backend.mapper.AccountMapper;
import org.example.backend.service.AccountService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {

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
}
