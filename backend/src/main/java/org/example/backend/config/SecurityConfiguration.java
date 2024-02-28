package org.example.backend.config;


import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.backend.Fileter.JwtAuthorizeFilter;
import org.example.backend.entity.ResultBean;
import org.example.backend.entity.dto.Account;
import org.example.backend.entity.vo.response.AuthorizeVO;
import org.example.backend.service.AccountService;
import org.example.backend.service.Impl.AccountServiceImpl;
import org.example.backend.utils.JwtUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.io.PrintWriter;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration {

    @Resource
    AccountService accountService;

    @Resource
    JwtUtils jwtUtils;

    @Resource
    JwtAuthorizeFilter jwtAuthorizeFilter;
    @Bean
    SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
        return security
                //验证
                .authorizeHttpRequests(conf ->{
                    conf.requestMatchers("/api/auth/**").permitAll();
                    conf.anyRequest().authenticated();
                })
                //登录
                .formLogin(conf ->{
                    conf.loginProcessingUrl("/api/auth/login");
                    conf.successHandler(authenticationSuccessHandler());
                    conf.failureHandler(authenticationFailureHandler());
                })
                //退出登录
                .logout(conf ->{
                    conf.logoutUrl("/api/auth/logout");
                    conf.logoutSuccessHandler(logoutSuccessHandler());
                })
                //csrf
                .csrf(AbstractHttpConfigurer::disable)
                //跨域
                .cors(conf->{
                    //新建corsConfiguration
                    CorsConfiguration configuration = new CorsConfiguration();
                    configuration.addAllowedOrigin("http://localhost:5173");
                    configuration.addAllowedMethod("*");
                    configuration.addAllowedHeader("*");
                    configuration.addExposedHeader("*");
                    configuration.setAllowCredentials(false);//发送cookie
                    //创建source
                    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                    source.registerCorsConfiguration("/**", configuration);
                    conf.configurationSource(source);
                })
                //无状态
                .sessionManagement(conf->conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //添加过滤器
                .addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class)
                //未登录
                .exceptionHandling(conf->{
                    //没有登录
                    conf.authenticationEntryPoint(new AuthenticationEntryPoint() {
                        @Override
                        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                            response.setCharacterEncoding("UTF-8");
                            response.setContentType("application/json");
                            response.getWriter().write(ResultBean.failure(401, authException.getMessage()).asJOSNString());
                        }
                    });
                    //角色无权限
                    conf.accessDeniedHandler(new AccessDeniedHandler() {
                        @Override
                        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                            response.setCharacterEncoding("UTF-8");
                            response.setContentType("application/json");
                            response.getWriter().write(ResultBean.failure(403, accessDeniedException.getMessage()).asJOSNString());
                        }
                    });
                })
//                .userDetailsService(accountService)
                .build();
    }
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                User user = (User) authentication.getPrincipal();
                Account account = accountService.findAccountByUsernameOrEmail(user.getUsername());
                String token = jwtUtils.createJwt(user, account.getId(), account.getUsername());
                //AuthorizeVO authorizeVO = new AuthorizeVO();
                //BeanUtils.copyProperties(account,authorizeVO);
                //通过反射
                AuthorizeVO authorizeVO = account.asViewObject(AuthorizeVO.class, v ->{
                    v.setExpire(jwtUtils.expireTime());
                    v.setToken(token);
                });
                response.getWriter().write(ResultBean.success(authorizeVO,"登录成功").asJOSNString());
            }
        };
    }
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(){
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write(ResultBean.failure(401,"登录失败,用户名或密码错误").asJOSNString());
            }
        };
    }
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(){
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                PrintWriter writer = response.getWriter();
                String authorization = request.getHeader("Authorization");
                if(jwtUtils.validateJwt(authorization)){
                    writer.write(ResultBean.success("退出登陆成功").asJOSNString());
                }else {
                    writer.write(ResultBean.failure(400,"退出登录失败").asJOSNString());
                }
            }
        };
    }
}
