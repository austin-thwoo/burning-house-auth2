package auth.exception;


import globalCommon.error.exception.BusinessException;
import globalCommon.error.model.ErrorCode;

public class UserNameDuplicatedException extends BusinessException {
    public UserNameDuplicatedException(String value) {
        super(value, ErrorCode.DUPLICATED_ID);
    }
}
