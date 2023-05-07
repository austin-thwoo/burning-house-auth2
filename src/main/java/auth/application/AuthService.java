package auth.application;


import auth.exception.UserNameDuplicatedException;
import auth.persistance.UserJpaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;


@RequiredArgsConstructor
@Transactional
@Service
public class AuthService {

    private final UserJpaRepository userJpaRepository;

    public Boolean usernameOverLap(String userName) {
          boolean exist = userJpaRepository.existsByUsername(userName);

        if (exist) {
            throw new UserNameDuplicatedException(userName);
        }
        return true;
    }
}
