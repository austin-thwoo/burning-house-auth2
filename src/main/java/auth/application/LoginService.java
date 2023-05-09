package auth.application;


import auth.domain.User;
import auth.dto.request.LoginCommand;
import auth.dto.request.TokenDTO;
import auth.dto.response.TokenResponse;
import auth.exception.DeletedUserException;
import auth.exception.InvalidPasswordException;
import auth.exception.UserNotFoundException;
import auth.persistance.UserJpaRepository;
import auth.provider.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Optional;

@RequiredArgsConstructor
@Service
@Transactional
public class LoginService {
    private final PasswordEncoder passwordEncoder;
//    private final UserRepositorySupport userRepositorySupport;
    private final UserJpaRepository userJpaRepository;
    private final TokenProvider tokenProvider;
    public TokenResponse login(LoginCommand loginCommand) {

        User user=getUser(loginCommand);
        checkDeleteUser(user);
        TokenDTO tokenDTO= new TokenDTO(getToken(user),user);
        return new TokenResponse(tokenDTO);
    }

    private String getToken(User user) {
        return tokenProvider.createToken(user.getId().toString(),user.getRoles());
    }

    private User getUser(LoginCommand loginCommand) {
//    return userRepositorySupport.findByUserName(loginCommand.getUsername());
        return new User();

    }

    private void checkDeleteUser(User user) {
        if (user.getDeletedDate()!=null){
            throw new DeletedUserException(user.getId().toString());
        }
    }
    public void checkPassword(String password, String encodedPassword) {
        if (!passwordEncoder.matches(password, encodedPassword)) {
            throw new InvalidPasswordException(password);
        }
    }

    public String idCheck(User principal) {
        Long id =principal.getId();
        Optional<User> result=userJpaRepository.findById(id);
        if (result.isEmpty()){
            throw new UserNotFoundException(id.toString());
        }
        return result.get().getUsername();

    }
}
