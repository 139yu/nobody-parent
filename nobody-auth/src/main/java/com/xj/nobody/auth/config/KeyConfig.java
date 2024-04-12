package com.xj.nobody.auth.config;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyConfig {
    private static final String STORE_FILE = "jwt.jks";
    private static final String STORE_PASSWORD = "nobody";
    private static final String KEY_ALIAS = "jwt";
    private static final KeyStoreKeyFactory KEY_STORE_KEY_FACTORY =
            new KeyStoreKeyFactory(new ClassPathResource(STORE_FILE), STORE_PASSWORD.toCharArray());
    static RSAPublicKey getVerifierKey() {
        return (RSAPublicKey) getKeyPair().getPublic();
    }

    static RSAPrivateKey getSingerKey(){
        return (RSAPrivateKey) getKeyPair().getPrivate();
    }

    private static KeyPair getKeyPair(){
        return KEY_STORE_KEY_FACTORY.getKeyPair(KEY_ALIAS);
    }
}
