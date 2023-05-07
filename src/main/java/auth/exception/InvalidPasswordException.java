package auth.exception;


import globalCommon.error.exception.BusinessException;
import globalCommon.error.model.ErrorCode;

public class InvalidPasswordException extends BusinessException {
    public InvalidPasswordException(String value) { super(value, ErrorCode.NOT_MATCH_PASSWORD);
    }
}
