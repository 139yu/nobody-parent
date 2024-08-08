package com.xj.nobody.admin.controller;

import com.xj.nobody.admin.domain.SysResource;
import com.xj.nobody.admin.service.SysResourceService;
import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.exception.BusinessException;
import com.xj.nobody.commons.validate.ValidateGroup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("resource")
public class SysResourceController {
    @Autowired
    private SysResourceService resourceService;

    @PostMapping("addResource")
    public CommonResult addResource(@RequestBody @Validated({ValidateGroup.AddGroup.class}) SysResource resource) throws BusinessException {
        resourceService.addResource(resource);
        return CommonResult.success();
    }

    @PostMapping("updateResource")
    public CommonResult updateResource(@RequestBody @Validated({ValidateGroup.UpdateGroup.class}) SysResource resource) throws BusinessException {
        resourceService.updateResource(resource);
        return CommonResult.success();
    }

    @PostMapping("deleteResource/{id}")
    public CommonResult deleteResource(@PathVariable Integer id) throws BusinessException {
        resourceService.deleteResource(id);
        return CommonResult.success();
    }
}
