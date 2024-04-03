package com.xj.nobody.admin;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
@MapperScan("com.xj.nobody.admin.mapper")
public class NobodyAdminApplication {
    public static void main(String[] args) {
        SpringApplication.run(NobodyAdminApplication.class, args);
    }
}
