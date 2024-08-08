package com.xj.nobody.admin.exception;

import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.exception.BusinessException;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    @ExceptionHandler(value = BusinessException.class)
    public CommonResult exceptionHandler(BusinessException e) {
        if (e.getErrorCode() != null) {
            return CommonResult.failed(e.getErrorCode());
        }
        LOGGER.error(e.getMessage());
        return CommonResult.failed(e.getMessage());
    }

    @ExceptionHandler(value = Exception.class)
    public CommonResult exception(Exception e) {
        LOGGER.error(e.getMessage());
        return CommonResult.failed();
    }
}
