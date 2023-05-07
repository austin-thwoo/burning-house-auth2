package auth.dto.request;


import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class UserRegisterCommand {


    private String username;
    private String password;
    public void setEncodedPassword(String encodedPassword) {
        this.password= encodedPassword;
    }
}
