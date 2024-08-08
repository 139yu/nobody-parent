package com.xj.nobody.admin.domain;

import com.baomidou.mybatisplus.annotation.TableField;
import com.xj.nobody.commons.validate.ValidateGroup;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Null;
import java.util.List;

@Data
public class SysResourceCategory {
    @NotNull(message = "id不能为空", groups = {ValidateGroup.UpdateGroup.class})
    @Null(message = "数据异常", groups = {ValidateGroup.AddGroup.class})
    private Integer id;
    @NotEmpty(message = "分类名称不能为空", groups = {ValidateGroup.AddGroup.class})
    private String name;
    @NotNull(message = "排序不能为空", groups = {ValidateGroup.AddGroup.class})
    private Integer sort;
    @TableField(exist = false)
    private List<SysResource> resources;
}
