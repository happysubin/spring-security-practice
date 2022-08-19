package spring.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import spring.security.domain.Account;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository <Account, Long> {
    Optional<Account> findByUsername(String username);
}
