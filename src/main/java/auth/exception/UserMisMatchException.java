package auth.exception;


import globalCommon.error.exception.BusinessException;
import globalCommon.error.model.ErrorCode;

public class UserMisMatchException extends BusinessException {

    public UserMisMatchException(String message) {
        super(message, ErrorCode.USER_MIS_MATCH);
    }
}
