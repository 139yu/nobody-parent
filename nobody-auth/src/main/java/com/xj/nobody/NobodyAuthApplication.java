package com.xj.nobody;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan({"com.xj.nobody.auth.study.auth.mapper"})
public class NobodyAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(NobodyAuthApplication.class);
    }


}
