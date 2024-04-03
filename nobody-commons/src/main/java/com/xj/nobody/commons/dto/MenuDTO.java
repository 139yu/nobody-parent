package com.xj.nobody.commons.dto;

import lombok.Data;

@Data
public class MenuDTO {
    private Integer id;
    private String title;
    private String path;
    private String perms;
}
