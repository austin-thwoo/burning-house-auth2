package auth.persistance;


import auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserJpaRepository extends JpaRepository<User,Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String userName);
}
