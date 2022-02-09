package g46.kun.uz.service;

import g46.kun.uz.converter.ProfileConverter;
import g46.kun.uz.dto.FilterDTO;
import g46.kun.uz.dto.ProfileDTO;
import g46.kun.uz.dto.ProfileFilterDTO;
import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.exp.ItemNotFoundException;
import g46.kun.uz.exp.ServerBadRequestException;
import g46.kun.uz.repository.ProfileRepository;
import g46.kun.uz.repository.impl.ProfileCustomRepository;
import g46.kun.uz.types.ProfileStatus;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import javax.persistence.criteria.*;
import java.time.LocalDateTime;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ProfileService {
    @Autowired
    private ProfileRepository profileRepository;
    @Autowired
    private ProfileCustomRepository profileCustomRepository;

    public ProfileDTO create(ProfileDTO dto) {

        Optional<ProfileEntity> optional = profileRepository.getByEmail(dto.getEmail());
        if (optional.isPresent()) {
            throw new ServerBadRequestException("Email already exists.");
        }

        ProfileEntity entity = new ProfileEntity();
        entity.setName(dto.getName());

        entity.setSurname(dto.getSurname());

        entity.setEmail(dto.getEmail());
        entity.setContact(dto.getContact());
        entity.setRole(dto.getRole());
        entity.setStatus(dto.getStatus());
        entity.setCreatedDate(LocalDateTime.now());
        entity.setPassword(DigestUtils.md5Hex(dto.getPassword()));

        this.profileRepository.save(entity);

        dto.setId(entity.getId());
        dto.setCreatedDate(entity.getCreatedDate());
        dto.setPassword(null);
        return dto;
    }

    public ProfileDTO getById(Integer id) {
        ProfileEntity profileEntity = get(id);
        return ProfileConverter.toDTO(profileEntity);
    }

    public Boolean update(Integer id, ProfileDTO dto) {
        ProfileEntity entity = get(id);

        entity.setName(dto.getName());
        entity.setSurname(dto.getSurname());
        entity.setEmail(dto.getEmail());
        entity.setContact(dto.getContact());
        entity.setRole(dto.getRole());
        this.profileRepository.save(entity);

        return true;
    }

    public Boolean changeStatus(Integer id, ProfileStatus status) {
        this.profileRepository.updateStatus(status, id);
        return true;
    }

    public List<ProfileDTO> getList() {
//        List<ProfileEntity> entityList = this.profileRepository.findAll();
//        List<ProfileDTO> dtoList = new LinkedList<>();
//        for (ProfileEntity entity : entityList) {
//            dtoList.add(ProfileConverter.toDTO(entity));
//        }
//        return dtoList;

//        entityList.forEach(profileEntity -> {
//            dtoList.add(ProfileConverter.toDTO(profileEntity));
//        });
//        dtoList = entityList
//                .stream()
//                .map(ProfileConverter::toDTO)
//                .collect(Collectors.toList());

        return this.profileRepository.findAll()
                .stream()
                .map(profileEntity -> ProfileConverter.toDTO(profileEntity))
                .collect(Collectors.toList());
    }

    public Page<ProfileDTO> getListForPagination(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);

        Page<ProfileEntity> paging = this.profileRepository.findAll(pageable);

        Long totalElements = paging.getTotalElements();
        Integer totalPages = paging.getTotalPages();
        List<ProfileEntity> content = paging.getContent();

        Page<ProfileDTO> resultPage = paging.map(ProfileConverter::toDTO);

        return resultPage;
    }

    public List<ProfileDTO> filter(ProfileFilterDTO profileFilterDTO) {
        return null;
    }

    public ProfileEntity get(Integer id) {
        Optional<ProfileEntity> optional = this.profileRepository.findById(id);
        if (!optional.isPresent()) {
            throw new ItemNotFoundException("Profile topilmadi");
        }
        return optional.get();
    }

    public void testJon(FilterDTO dto) {
//        this.profileCustomRepository.filterJon(dto);

        Specification<ProfileEntity> specification = (root, criteriaQuery, criteriaBuilder) -> {
            Predicate namePredicate = criteriaBuilder.equal(root.get("name"), dto.getName());
            Predicate surnamePredicate = criteriaBuilder.equal(root.get("surname"), dto.getSurname());

            return criteriaBuilder.and(namePredicate, surnamePredicate);
        };

        List<ProfileEntity> profileEntityList = this.profileRepository.findAll(specification);
        profileEntityList.forEach(profileEntity -> {
            System.out.println(profileEntity.getName());
        });
    }

    public boolean isValid(ProfileDTO dto) {
        if (dto.getEmail() == null || dto.getEmail().isEmpty() || dto.getEmail().trim().length() < 6) {
            return false;
        } else if (dto.getName() == null || dto.getName().isEmpty() || dto.getName().length() < 2) {
            return false;
        }
        // ....
        return true;
    }

}
