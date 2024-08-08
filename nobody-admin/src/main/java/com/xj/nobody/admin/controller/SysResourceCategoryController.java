package com.xj.nobody.admin.controller;

import com.xj.nobody.admin.domain.SysResourceCategory;
import com.xj.nobody.admin.service.SysResourceCategoryService;
import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.exception.BusinessException;
import com.xj.nobody.commons.validate.ValidateGroup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("resourceCategory")
public class SysResourceCategoryController {
    @Autowired
    private SysResourceCategoryService resourceCategoryService;

    @GetMapping("listWithItem")
    public CommonResult listWithItem() {
        return CommonResult.success(resourceCategoryService.listWithItem());
    }

    @GetMapping("list")
    public CommonResult list(SysResourceCategory params) {
        return CommonResult.success(resourceCategoryService.list(params));
    }

    @PostMapping("addCategory")
    public CommonResult addCategory(@RequestBody @Validated({ValidateGroup.AddGroup.class}) SysResourceCategory resourceCategory) throws BusinessException {
        resourceCategoryService.addCategory(resourceCategory);
        return CommonResult.success();
    }

    @PostMapping("updateCategory")
    public CommonResult updateCategory(@RequestBody @Validated({ValidateGroup.UpdateGroup.class}) SysResourceCategory resourceCategory) throws BusinessException {
        resourceCategoryService.updateCategory(resourceCategory);
        return CommonResult.success();
    }

    @PostMapping("deleteCategory/{id}")
    public CommonResult deleteCategory(@PathVariable Integer id) throws BusinessException {
        resourceCategoryService.deleteCategory(id);
        return CommonResult.success();
    }
}
