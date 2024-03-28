package com.xj.nobody.resource.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.annotation.PostConstruct;

@Configuration
public class OAuth2ResourceServerSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Value("${spring.security.oauth2.resourceserver.opaque.introspection-uri}")
    String introspectionUri;
    @Value("${spring.security.oauth2.resourceserver.opaque.introspection-client-id}")
    String clientId;
    @Value("${spring.security.oauth2.resourceserver.opaque.introspection-client-secret}")
    String clientSecret;
    @PostConstruct
    public void init(){
        System.out.println(1234);
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .oauth2ResourceServer().opaqueToken()
                .introspectionUri(introspectionUri)
                .introspectionClientCredentials(clientId, clientSecret);
    }
}
