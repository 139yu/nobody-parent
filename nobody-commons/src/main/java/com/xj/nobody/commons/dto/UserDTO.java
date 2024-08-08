package com.xj.nobody.commons.dto;

import lombok.Data;

import java.util.List;

@Data
public class UserDTO {
    private Integer userId;
    private String username;
    private String password;
    private Integer enable;
    private String clientId;
    //权限字符串
    private List<String> roleList;
}
