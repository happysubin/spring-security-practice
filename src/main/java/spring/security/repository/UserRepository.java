package spring.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import spring.security.domain.Account;

@Repository
public interface UserRepository extends JpaRepository <Account, Long> {
}
