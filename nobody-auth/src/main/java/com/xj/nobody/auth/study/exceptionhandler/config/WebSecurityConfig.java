package com.xj.nobody.auth.study.exceptionhandler.config;

import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

//@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        AntPathRequestMatcher qqMatch = new AntPathRequestMatcher("/qq/**");
        AntPathRequestMatcher wxMatch = new AntPathRequestMatcher("/wx/**");
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and().formLogin()
                .and().exceptionHandling()
                .defaultAuthenticationEntryPointFor(((request, response, authException) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType("text/html;charset=utf-8");
                    response.getWriter().write("请登录QQ");
                }),qqMatch)
                .defaultAccessDeniedHandlerFor(((request, response, accessDeniedException) -> {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.setContentType("text/html;charset=utf-8");
                    response.getWriter().write("QQ用户权限不足");
                }),qqMatch)
                .defaultAuthenticationEntryPointFor(((request, response, authException) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType("text/html;charset=utf-8");
                    response.getWriter().write("请登录WX");
                }),wxMatch)
                .defaultAccessDeniedHandlerFor(((request, response, accessDeniedException) -> {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.setContentType("text/html;charset=utf-8");
                    response.getWriter().write("WX用户权限不足");
                }),qqMatch)
                .and().csrf().disable();
    }
}
