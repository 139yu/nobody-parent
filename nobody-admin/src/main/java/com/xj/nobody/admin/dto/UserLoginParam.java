package com.xj.nobody.admin.dto;

import lombok.Data;

import javax.validation.constraints.NotEmpty;

@Data
public class UserLoginParam {
    @NotEmpty(message = "请输入用户名")
    private String username;
    @NotEmpty(message = "请输入密码")
    private String password;
}
