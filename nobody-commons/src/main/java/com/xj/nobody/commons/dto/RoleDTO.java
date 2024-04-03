package com.xj.nobody.commons.dto;

import lombok.Data;

import java.util.List;

@Data
public class RoleDTO {
    private Integer id;
    private String roleKey;
    private List<MenuDTO> menuList;
}
