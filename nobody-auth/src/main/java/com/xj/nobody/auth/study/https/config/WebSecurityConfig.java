package com.xj.nobody.auth.study.https.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .portMapper().http(8080).mapsTo(8443)
                .and()
                .requiresChannel().antMatchers("/https/**")
                //要求协议是https
                .requiresSecure()
                .antMatchers("/http/**")
                //要求协议是http
                .requiresInsecure()
                .and().csrf().disable();
    }
}
