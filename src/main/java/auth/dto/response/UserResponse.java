package auth.dto.response;


import auth.domain.User;
import lombok.Getter;


@Getter
public class UserResponse {
    private final Long id;
    private final String username;
    private final String password;
    private final RoleResponse roleResponse;


    public UserResponse(User user){
        this.id = user.getId();
        this.username= user.getUsername();
        this.password=user.getPassword();
        this.roleResponse=new RoleResponse(user.getRoles());
    }
}
