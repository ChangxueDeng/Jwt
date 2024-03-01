package org.example.backend.controller;


import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import org.example.backend.entity.ResultBean;
import org.example.backend.service.AccountService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
        String message = accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr());
        if(message == null){
            return ResultBean.success();
        }else return ResultBean.failure(400, message);
    }

}
