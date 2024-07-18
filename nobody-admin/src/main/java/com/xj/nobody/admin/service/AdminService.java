package com.xj.nobody.admin.service;

import com.xj.nobody.commons.api.CommonResult;

public interface AdminService {
    public CommonResult login(String username, String password);
}
