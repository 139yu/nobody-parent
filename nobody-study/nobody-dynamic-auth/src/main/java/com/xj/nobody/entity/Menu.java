package com.xj.nobody.entity;

import lombok.Data;

import java.util.List;

@Data
public class Menu {
    private Integer id;
    private String pattern;
    private List<Role> roles;

}
