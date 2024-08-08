package com.xj.nobody.gateway.authorization;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.convert.Convert;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import com.nimbusds.jose.JWSObject;
import com.xj.nobody.commons.constants.AuthConstants;
import com.xj.nobody.commons.constants.RedisKey;
import com.xj.nobody.commons.dto.UserDTO;
import com.xj.nobody.gateway.config.IgnoreUrlConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
@Component
public class AuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    @Autowired
    private IgnoreUrlConfig ignoreUrlConfig;

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> mono, AuthorizationContext authorizationContext) {
        ServerHttpRequest request = authorizationContext.getExchange().getRequest();
        URI uri = request.getURI();
        String path = uri.getPath();
        //白名单
        PathMatcher pathMatcher = new AntPathMatcher();
        for (String ignoreUrl : ignoreUrlConfig.getUrls()) {
            if (pathMatcher.match(ignoreUrl, path)){
                return Mono.just(new AuthorizationDecision(true));
            }
        }
        //预检请求放行
        if (request.getMethod() == HttpMethod.OPTIONS){
            return Mono.just(new AuthorizationDecision(true));
        }
        String token = request.getHeaders().getFirst(AuthConstants.JWT_TOKEN_HEADER);
        if (StrUtil.isEmpty(token)) {
            return Mono.just(new AuthorizationDecision(false));
        }

        try {
            String realToken = token.replace(AuthConstants.AUTH_TOKEN_PREFIX, "");
            JWSObject jwsObject = JWSObject.parse(realToken);
            String userStr = jwsObject.getPayload().toString();
            UserDTO userDTO = JSONUtil.toBean(userStr, UserDTO.class);
            String clientId = userDTO.getClientId();
            //对clientId过滤
        }
        catch (ParseException e) {
            e.printStackTrace();
            return Mono.just(new AuthorizationDecision(false));
        }
        Map<Object, Object> resourceRoleMap = redisTemplate.opsForHash().entries(RedisKey.ROLE_RESOURCE);
        Iterator<Object> iterator = resourceRoleMap.keySet().iterator();
        //保存访问当前请求所需要的角色
        List<String> authorizes = new ArrayList<>();
        while (iterator.hasNext()){
            String pattern = (String) iterator.next();
            if (pathMatcher.match(pattern, path)) {
                authorizes.addAll(Convert.toList(String.class, resourceRoleMap.get(pattern)));
            }
        }
        authorizes = authorizes.stream().map(item -> AuthConstants.AUTHORITY_PREFIX + item).collect(Collectors.toList());
        //不需要权限
        if (CollectionUtil.isEmpty(authorizes)) {
            return Mono.just(new AuthorizationDecision(true));
        }
        return mono
                .filter(Authentication::isAuthenticated)
                //获取当前用户具有的角色
                .flatMapIterable(Authentication::getAuthorities)
                .map(GrantedAuthority::getAuthority)
                //用户具有的角色是否在当前请求所需的角色中
                .any(authorizes::contains)
                .map(AuthorizationDecision::new)
                //默认没有权限
                .defaultIfEmpty(new AuthorizationDecision(false));
    }
}
