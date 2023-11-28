package com.xj.nobody.auth.study.session.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

//@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("root")
                .password("{noop}root")
                .roles("admin")
                ;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and().csrf().disable()
                .sessionManagement()
                .sessionFixation().changeSessionId()
                .maximumSessions(1)
                //.expiredUrl("/login")
                //.expiredSessionStrategy(event -> {
                //    HttpServletResponse response = event.getResponse();
                //    response.setContentType("application/json");
                //    Map<String,Object> res = new HashMap<>();
                //    res.put("msg","session is expired");
                //    response.getWriter().print(res);
                //    response.flushBuffer();
                //})
                .maxSessionsPreventsLogin(true)
                .and()
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        ;
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher(){
        return new HttpSessionEventPublisher();
    }


}
