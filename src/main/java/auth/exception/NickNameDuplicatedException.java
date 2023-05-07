package auth.exception;


import globalCommon.error.exception.BusinessException;
import globalCommon.error.model.ErrorCode;

public class NickNameDuplicatedException extends BusinessException {
    public NickNameDuplicatedException(String value) {
        super(value, ErrorCode.DUPLICATED_NICKNAME);
    }
}
