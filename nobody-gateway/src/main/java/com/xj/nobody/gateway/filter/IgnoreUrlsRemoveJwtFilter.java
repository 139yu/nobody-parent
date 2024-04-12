package com.xj.nobody.gateway.filter;

import com.xj.nobody.commons.constants.AuthConstants;
import com.xj.nobody.gateway.config.IgnoreUrlConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;

@Component
public class IgnoreUrlsRemoveJwtFilter implements WebFilter {
    @Autowired
    private IgnoreUrlConfig ignoreUrlConfig;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        List<String> urls = ignoreUrlConfig.getUrls();
        ServerHttpRequest request = exchange.getRequest();
        URI uri = request.getURI();
        PathMatcher pathMatcher = new AntPathMatcher();
        for (String url : urls) {
            if (pathMatcher.match(url, uri.getPath())) {
                request = exchange.getRequest().mutate().header(AuthConstants.JWT_TOKEN_HEADER,"").build();
                exchange = exchange.mutate().request(request).build();
                return chain.filter(exchange);
            }
        }
        return null;
    }
}
