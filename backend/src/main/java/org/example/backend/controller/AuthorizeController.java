package org.example.backend.controller;


import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import org.example.backend.entity.ResultBean;
import org.example.backend.entity.vo.request.EmailRegisterVO;
import org.example.backend.service.AccountService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.function.Supplier;

@RestController
@Validated
@RequestMapping("/api/auth")
public class AuthorizeController {
    @Resource
    AccountService accountService;

    @GetMapping("/ask-code")
    public ResultBean<Void> askVerifyCode(@RequestParam @Email String email,
                                          @RequestParam  @Pattern(regexp = "register|reset") String type,
                                          HttpServletRequest request){
        return this.messageHandle(()->
                accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr()));
    }
    @PostMapping("/register")
    public ResultBean<Void> register(@RequestBody EmailRegisterVO emailRegisterVO){
        return this.messageHandle(()-> accountService.registerEmailAccount(emailRegisterVO));
    }

    private ResultBean<Void> messageHandle(Supplier<String> action){
        String message = action.get();
        return message == null ? ResultBean.success() : ResultBean.failure(400, message);
    }
}
