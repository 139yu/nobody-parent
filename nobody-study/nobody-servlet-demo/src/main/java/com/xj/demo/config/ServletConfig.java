package com.xj.demo.config;

import com.xj.demo.servlet.TestServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServletConfig {
    @Bean
    public ServletRegistrationBean<TestServlet> registrationServlet(){
        return new ServletRegistrationBean<>(new TestServlet(),"/test");
    }
}
