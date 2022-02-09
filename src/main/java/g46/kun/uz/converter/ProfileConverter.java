package g46.kun.uz.converter;

import g46.kun.uz.dto.ProfileDTO;
import g46.kun.uz.entity.ProfileEntity;

public class ProfileConverter {


    public static ProfileDTO toDTO(ProfileEntity entity) {
        ProfileDTO dto = new ProfileDTO();
        dto.setId(entity.getId());
        dto.setName(entity.getName());
        dto.setSurname(entity.getSurname());
        dto.setEmail(entity.getEmail());
        dto.setContact(entity.getContact());
        dto.setStatus(entity.getStatus());
        dto.setRole(entity.getRole());
        dto.setCreatedDate(entity.getCreatedDate());
        return dto;
    }

    public static Object toDTO(Object o) {
        return null;
    }
}
