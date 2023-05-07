package auth.exception;


import globalCommon.error.exception.BusinessException;
import globalCommon.error.model.ErrorCode;

public class DeletedUserException extends BusinessException {

    public DeletedUserException(String message) {
        super(message, ErrorCode.USER_DELETED);
    }
}
