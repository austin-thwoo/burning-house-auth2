package auth.exception;


import globalCommon.error.exception.BusinessException;
import globalCommon.error.model.ErrorCode;

public class DuplicationPasswordException extends BusinessException {
    public DuplicationPasswordException(String value) { super(value, ErrorCode.NOT_MATCH_PASSWORD);
    }
}
