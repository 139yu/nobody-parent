package com.xj.nobody.auth.feign;

import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "nobody-admin")
public interface AdminFeignClient {
    @GetMapping("/admin/loadByUsername")
    UserDTO loadUserByUsername(String username);
}
