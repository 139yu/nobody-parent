package com.xj.nobody.gateway.config;

import cn.hutool.core.util.ArrayUtil;
import com.xj.nobody.commons.constants.AuthConstants;
import com.xj.nobody.gateway.authorization.AuthorizationManager;
import com.xj.nobody.gateway.component.RestAuthenticationEntryPoint;
import com.xj.nobody.gateway.component.RestfulAccessDeniedHandler;
import com.xj.nobody.gateway.filter.IgnoreUrlsRemoveJwtFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

/**
 * 资源服务配置
 */
@Configuration
@EnableWebFluxSecurity
@AllArgsConstructor
public class ResourceServerConfig {
    private final AuthorizationManager authorizationManager;
    private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;
    private final RestfulAccessDeniedHandler restfulAccessDeniedHandler;
    private final IgnoreUrlsRemoveJwtFilter ignoreUrlsRemoveJwtFilter;
    private final IgnoreUrlConfig ignoreUrlConfig;


    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter());
        //处理jwt请求头过期或签名错误
        http.oauth2ResourceServer().authenticationEntryPoint(restAuthenticationEntryPoint);
        //白名单请求移除JWT请求头
        http.addFilterBefore(ignoreUrlsRemoveJwtFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        http
                .authorizeExchange()
                //白名单放行
                .pathMatchers(ArrayUtil.toArray(ignoreUrlConfig.getUrls(), String.class))
                .permitAll()
                //鉴权管理器
                .anyExchange().access(authorizationManager)
                //未授权处理
                .and().exceptionHandling().accessDeniedHandler(restfulAccessDeniedHandler)
                //未认证处理
                .authenticationEntryPoint(restAuthenticationEntryPoint)
                .and().csrf().disable();
        return http.build();
    }

    @Bean
    public Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthorityPrefix(AuthConstants.AUTHORITY_PREFIX);
        converter.setAuthoritiesClaimName(AuthConstants.AUTHORITY_CLAIM_NAME);
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(converter);
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }
}
