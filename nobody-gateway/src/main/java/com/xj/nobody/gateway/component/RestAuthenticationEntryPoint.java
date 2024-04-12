package com.xj.nobody.gateway.component;

import cn.hutool.json.JSONUtil;
import com.xj.nobody.commons.api.CommonResult;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 未登录或token失效时返回结果
 */
@Component
public class RestAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.OK);
        response.getHeaders().set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.getHeaders().set("Access-Control-Allow-Origin","*");
        response.getHeaders().set("Cache-Control","no-cache");
        CommonResult<String> unauthorized = CommonResult.unauthorized(ex.getMessage());
        String jsonResult = JSONUtil.toJsonStr(unauthorized);
        DataBuffer buffer = response.bufferFactory().wrap(jsonResult.getBytes());
        return response.writeWith(Mono.just(buffer));
    }
}
