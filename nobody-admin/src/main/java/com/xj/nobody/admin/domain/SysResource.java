package com.xj.nobody.admin.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.xj.nobody.commons.validate.ValidateGroup;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Null;

/**
 * 资源
 */
@Data
public class SysResource {
    @Null(message = "数据异常",groups = {ValidateGroup.AddGroup.class})
    @NotNull(message = "id不能为空",groups = {ValidateGroup.UpdateGroup.class})
    @TableId(type = IdType.AUTO)
    private Integer id;
    @NotEmpty(message = "资源名称不能为空",groups = {ValidateGroup.AddGroup.class})
    private String name;
    @NotEmpty(message = "url不能为空",groups = {ValidateGroup.AddGroup.class})
    private String url;
    @NotNull(message = "请选择分类",groups = {ValidateGroup.AddGroup.class})
    private String categoryId;
    private String description;
}
