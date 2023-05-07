package auth.application;


import auth.domain.User;
import auth.dto.request.TokenDTO;
import auth.dto.request.UserRegisterCommand;
import auth.dto.response.TokenResponse;
import auth.exception.UserNameDuplicatedException;
import auth.persistance.UserJpaRepository;
import auth.provider.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class RegisterService {

    private final UserJpaRepository userJpaRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider jwtTokenProvider;

    public TokenResponse register(UserRegisterCommand registerCommand) {
        User savedUser=this.save(registerCommand);
        TokenDTO dto = new TokenDTO(getToken(savedUser), savedUser);


        return new TokenResponse(dto);
    }

    public User save(UserRegisterCommand registerCommand) {

        return place(registerCommand);
    }



    public User place(UserRegisterCommand registerCommand) {


        checkUserName(registerCommand.getUsername());
//        checkUserEmail(registerCommand.getUserEmail());
        registerCommand.setEncodedPassword(passwordEncoder.encode(registerCommand.getPassword()));
        User user = User.create(registerCommand);
        user.addRole("ROLE_USER");

        return userJpaRepository.save(user);

    }
//리드온리
    private void checkUserName(String username) {
        Optional<User> user = userJpaRepository.findByUsername(username);
        if (user.isPresent()) {
            throw new UserNameDuplicatedException(username);
        }


    }
    private String getToken(User user) {
        return jwtTokenProvider.createToken(user.getId().toString(), user.getRoles());
    }
}
