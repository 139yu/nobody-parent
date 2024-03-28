package com.xj.nobody.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Configuration
public class WebClientConfig {
    /**
     * 用来发网络请求
     * @param authorizedClientManager
     * @return
     */
    @Bean
    WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager){
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        return WebClient.builder().apply(oauth2Client.oauth2Configuration()).build();
    }

    /**
     * 用来管理授权的客户端，通过OAuth2AuthorizedClientProvider对不同的客户端进行授权
     * @param clientRegistrationRepository
     * @param authorizedClientRepository
     * @return
     */
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                          OAuth2AuthorizedClientRepository authorizedClientRepository){
        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .clientCredentials()
                .password()
                .build();
        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        authorizedClientManager.setContextAttributesMapper(contextAttributesMapper());
        return authorizedClientManager;
    }

    private Function<OAuth2AuthorizeRequest, Map<String,Object>> contextAttributesMapper(){
        return authorizeRequest -> {
            Map<String, Object> contextAttributes = Collections.emptyMap();
            HttpServletRequest request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
            String username = request.getParameter(OAuth2ParameterNames.USERNAME);
            String password = request.getParameter(OAuth2ParameterNames.PASSWORD);
            if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
                contextAttributes = new HashMap<>();
                contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME,username);
                contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME,password);
            }
            return contextAttributes;
        };
    }
}
