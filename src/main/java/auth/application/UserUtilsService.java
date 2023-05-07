package auth.application;



import auth.exception.InvalidPasswordException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserUtilsService {

    public void checkEqualsNewPassword(String newPassword, String checkNewPassword) {
        if (!newPassword.equals(checkNewPassword)) {
            throw new InvalidPasswordException(newPassword + "!=" + checkNewPassword);
        }
    }

}
