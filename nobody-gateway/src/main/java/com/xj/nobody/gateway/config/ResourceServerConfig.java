package com.xj.nobody.gateway.config;

import com.xj.nobody.commons.constants.AuthConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class ResourceServerConfig {
    @Autowired
    ServerAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    private ServerAccessDeniedHandler accessDeniedHandler;
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter())
        .and().authenticationEntryPoint(authenticationEntryPoint).accessDeniedHandler(accessDeniedHandler)
        //.and().addFilterBefore()
        ;

        return null;
    }
    @Bean
    public Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix(AuthConstants.AUTHORITY_PREFIX);
        authoritiesConverter.setAuthoritiesClaimName(AuthConstants.AUTHORITY_CLAIM_NAME);
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }
}
