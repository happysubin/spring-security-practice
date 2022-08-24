package spring.security.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.domain.entity.AccessIp;

public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {

    AccessIp findByIpAddress(String IpAddress);
}
