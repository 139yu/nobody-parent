package com.xj.nobody.admin.service;

import com.xj.nobody.admin.vo.FullUserInfoVo;
import com.xj.nobody.commons.api.CommonResult;

public interface AdminService {
    /**
     * 登录
     * @param username
     * @param password
     * @return
     */
    public CommonResult login(String username, String password);


}
