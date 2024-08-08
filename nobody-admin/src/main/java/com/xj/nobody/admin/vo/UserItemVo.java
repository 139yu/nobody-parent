package com.xj.nobody.admin.vo;

import lombok.Data;

import java.util.Date;

@Data
public class UserItemVo {
    private Integer id;
    private String username;
    private String nickname;
    private String phone;
    private String avatar;
    private Date loginTime;
    private String email;
    private Integer enable;
}
