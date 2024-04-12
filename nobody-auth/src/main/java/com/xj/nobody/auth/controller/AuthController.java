package com.xj.nobody.auth.controller;

import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.constants.AuthConstants;
import com.xj.nobody.commons.dto.OAuth2TokenDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("oauth")
public class AuthController {
    @Autowired
    private TokenEndpoint tokenEndpoint;

    /**
     * 获取token
     *
     * @param grantType     授权模式
     * @param clientId      客户端id
     * @param client_secret 密钥
     * @param refreshToken
     * @param username
     * @param password
     * @return
     */
    @PostMapping("token")
    public CommonResult<OAuth2TokenDTO> postAccessToken(
            HttpServletRequest request,
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String client_secret,
            @RequestParam("refresh_token") String refreshToken,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password
    ) throws HttpRequestMethodNotSupportedException {
        Principal principal = request.getUserPrincipal();
        Map<String, String> parameters = new HashMap<>();
        parameters.put("grant_type",grantType);
        parameters.put("client_id",clientId);
        parameters.put("client_secret",client_secret);
        parameters.putIfAbsent("refresh_token",refreshToken);
        parameters.putIfAbsent("username",username);
        parameters.putIfAbsent("password",password);
        OAuth2AccessToken token = tokenEndpoint.postAccessToken(principal, parameters).getBody();
        OAuth2TokenDTO tokenDto = OAuth2TokenDTO
                .builder()
                .token(token.getValue())
                .expiresIn(token.getExpiresIn())
                .refreshToken(token.getRefreshToken().getValue())
                .tokenHead(AuthConstants.AUTH_TOKEN_PREFIX).build();
        return CommonResult.success(tokenDto);
    }
}
