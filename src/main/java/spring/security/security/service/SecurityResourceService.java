package spring.security.security.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;
import spring.security.domain.entity.Resources;
import spring.security.repository.ResourcesRepository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

@Service
@Slf4j
public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();

        resourcesList.forEach(resource ->
                {
                    List<ConfigAttribute> configAttributeList = new ArrayList<>();
                    resource.getRoleSet().forEach(role -> {
                        configAttributeList.add(new SecurityConfig(role.getRoleName()));
                        result.put(new AntPathRequestMatcher(resource.getResourceName()), configAttributeList); //권한의 순서에 주의하자!!!!
                    });
                }
        );
        log.debug("cache test");
        return result;
    }
}
