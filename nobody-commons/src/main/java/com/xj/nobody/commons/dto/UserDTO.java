package com.xj.nobody.commons.dto;

import lombok.Data;

import java.util.List;

@Data
public class UserDTO {
    private Long id;
    private String username;
    private String password;
    private Integer status;
    //权限字符串
    private List<String> authorities;
}
