package com.xj.nobody;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@SpringBootApplication
@MapperScan({"com.xj.nobody.auth.study.auth.mapper"})
public class NobodyAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(NobodyAuthApplication.class);
    }

    @Bean
    public CookieSerializer httpSessionResolver(){
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        cookieSerializer.setSameSite("strict");
        return cookieSerializer;
    }
}
