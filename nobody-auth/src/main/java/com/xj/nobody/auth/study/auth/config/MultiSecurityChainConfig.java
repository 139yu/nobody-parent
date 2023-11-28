package com.xj.nobody.auth.study.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xj.nobody.auth.study.auth.filter.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.PrintWriter;

//@Configuration
public class MultiSecurityChainConfig {
    //@Configuration
    @Order(1)
    static class SecurityConfig01 extends WebSecurityConfigurerAdapter{

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/foo/**")
                    .authorizeRequests()
                    .and()
                    .formLogin()
                    .loginProcessingUrl("/foo/login")
                    .permitAll()
                    .and().csrf().disable();
        }
    }

    //@Configuration
    @Order(2)
    static class SecurityConfig02 extends WebSecurityConfigurerAdapter{

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/bar/**")
                    .authorizeRequests()
                    .and()
                    .formLogin()
                    .loginProcessingUrl("/foo/login")
                    .permitAll()
                    .and().csrf().disable();
        }
    }


    static class SecurityConfig03 extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/test/**")
                    .authorizeRequests()
                    .and()
                    .formLogin()
                    .and()
                    .csrf().disable()
                    .addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class);
        }
        @Bean
        public LoginFilter loginFilter() throws Exception {
            LoginFilter loginFilter = new LoginFilter();
            loginFilter.setAuthenticationManager(authenticationManager());
            loginFilter.setAuthenticationSuccessHandler(((request, response, authentication) -> {
                PrintWriter writer = response.getWriter();
                writer.write(new ObjectMapper().writeValueAsString(authentication));
            }));
            return loginFilter;
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            //TODO 定义登录用户
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManager() throws Exception {
            return super.authenticationManager();
        }
    }
}
