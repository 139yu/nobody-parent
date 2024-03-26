package com.xj.nobody;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.xj.nobody.mapper")
public class NobodyDynamicAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(NobodyDynamicAuthApplication.class, args);
    }
}
