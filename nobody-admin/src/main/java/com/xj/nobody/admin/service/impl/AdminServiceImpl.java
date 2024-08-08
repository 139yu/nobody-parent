package com.xj.nobody.admin.service.impl;

import com.xj.nobody.admin.feign.AuthFeignClient;
import com.xj.nobody.admin.service.AdminService;
import com.xj.nobody.admin.vo.FullUserInfoVo;
import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.constants.AuthConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class AdminServiceImpl implements AdminService {
    @Autowired
    private AuthFeignClient authFeignClient;
    @Override
    public CommonResult login(String username, String password) {
        Map<String,Object> params = new HashMap<>();
        params.put("username",username);
        params.put("password",password);
        params.put("client_id", AuthConstants.ADMIN_CLIENT_ID);
        params.put("grant_type",AuthConstants.DEFAULT_GRANT_TYPE);
        params.put("client_secret",AuthConstants.CLIENT_SECRET);
        return authFeignClient.postAccessToken(params);
    }

}
