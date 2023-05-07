package auth.dto.response;

import java.util.List;

public class RoleResponse {
    private String role;

    public RoleResponse(List<String> roles) {
        this.role = roles.stream().anyMatch(e -> e.equals("ROLE_ADMIN")) ?
                "ROLE_ADMIN" : roles.stream().anyMatch(e -> e.equals("ROLE_USER")) ?
                "ROLE_USER" : "NONE";
    }
}
