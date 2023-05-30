package auth.dto.response;

import java.util.List;
import java.util.Set;

public class RoleResponse {
    private String role;

    public RoleResponse(Set<String> roles) {
        this.role = roles.stream().anyMatch(e -> e.equals("ROLE_ADMIN")) ?
                "ROLE_ADMIN" : roles.stream().anyMatch(e -> e.equals("ROLE_USER")) ?
                "ROLE_USER" : "NONE";
    }
}
