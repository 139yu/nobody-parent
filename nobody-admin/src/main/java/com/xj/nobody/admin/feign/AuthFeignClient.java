package com.xj.nobody.admin.feign;

import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.dto.OAuth2TokenDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

@FeignClient(name = "nobody-auth")
public interface AuthFeignClient {
    @PostMapping("/oauth/token")
    public CommonResult<OAuth2TokenDTO> postAccessToken(@RequestParam Map<String,Object> params);
}
