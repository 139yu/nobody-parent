package com.xj.nobody.oauth2.config;

import com.xj.nobody.oauth2.entity.CustomerOAuth2User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and().oauth2Login().userInfoEndpoint()
                .customUserType(CustomerOAuth2User.class,"github")
                ;
    }
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        return new InMemoryClientRegistrationRepository(githubClientRegistration());
    }
    private ClientRegistration githubClientRegistration(){
        return ClientRegistration.withRegistrationId("github")
                .clientId("Iv1.7b0677047c106da2")
                .clientSecret("13448ed583e1fa74bbb4bc04055c19ecc8be9690")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .userNameAttributeName("id")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("http://localhost:9001/login/oauth2/code/github")
                .scope("all")
                .authorizationUri("https://github.com/login/oauth/authorize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .clientName("GitHub")
                .build()
                ;
    }
}
