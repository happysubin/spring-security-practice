package spring.security.repository;



import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.domain.entity.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByRoleName(String name);

    @Override
    void delete(Role role);

}
