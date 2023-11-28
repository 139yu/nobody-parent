package com.xj.nobody;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan({"com.xj.nobody.system.mapper"})
public class NobodySystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(NobodySystemApplication.class, args);
    }

}
