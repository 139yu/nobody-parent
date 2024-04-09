package com.xj.nobody.auth.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class AccessTokenConfig {
    @Bean
    TokenStore tokenStore(){
        return new JwtTokenStore(accessTokenConverter());
    }

    /**
     * 将OAuth2令牌转换为jwt格式
     * @return
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter(){
        //私钥签名
        RsaSigner signer = new RsaSigner(KeyConfig.getSingerKey());
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigner(signer);
        converter.setVerifier(new RsaVerifier(KeyConfig.getVerifierKey()));
        return converter;
    }

    /**
     * 获取公钥
     * @return
     */
    @Bean
    public JWKSet jwkSet() {
        RSAKey.Builder builder = new RSAKey
                .Builder(KeyConfig.getVerifierKey())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                ;
        return new JWKSet(builder.build());
    }
}
