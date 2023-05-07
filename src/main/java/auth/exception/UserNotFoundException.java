package auth.exception;


import globalCommon.error.exception.BusinessException;
import globalCommon.error.model.ErrorCode;

public class UserNotFoundException extends BusinessException {
    public UserNotFoundException(String value) {
        super(value, ErrorCode.USER_NOT_FOUND);
    }
}
