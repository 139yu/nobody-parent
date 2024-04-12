package com.xj.nobody.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 网关白名单
 */
@Data
@Component
@ConfigurationProperties(prefix = "secure.ignore")
public class IgnoreUrlConfig {
    private List<String> urls;
}
