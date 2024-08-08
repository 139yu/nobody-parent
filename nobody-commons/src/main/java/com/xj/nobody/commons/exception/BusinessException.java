package com.xj.nobody.commons.exception;

import com.xj.nobody.commons.api.IErrorCode;

public class BusinessException extends Exception {
    private IErrorCode errorCode;

    public BusinessException(IErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public BusinessException(String message) {
        super(message);
    }

    public IErrorCode getErrorCode() {
        return errorCode;
    }
}
