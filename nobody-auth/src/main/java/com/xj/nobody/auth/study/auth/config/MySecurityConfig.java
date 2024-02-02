package com.xj.nobody.auth.study.auth.config;

import com.xj.nobody.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserService userService;
    //@Override
    //protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //    auth.userDetailsService(userService);
    //}

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
                .failureUrl("/error.html")
                .permitAll()
        .and().logout()
        .and().csrf().disable()
        ;
    }





}
