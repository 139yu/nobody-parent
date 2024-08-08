package com.xj.nobody.admin.vo;

import com.xj.nobody.admin.domain.SysMenu;
import lombok.Data;

import java.util.List;

@Data
public class FullUserInfoVo {
    private Integer id;
    private String username;
    private String avatar;
    private List<String> resourceList;
    private List<SysMenu> menuList;
}
