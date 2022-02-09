package g46.kun.uz.converter;

import g46.kun.uz.dto.CategoryDTO;
import g46.kun.uz.entity.CategoryEntity;

public class CategoryConverter {

    public static CategoryDTO toDTO(CategoryEntity entity) {
        CategoryDTO dto = new CategoryDTO();
        dto.setId(entity.getId());
        dto.setNameUz(entity.getNameUz());
        dto.setNameRu(entity.getNameRu());
        dto.setNameEn(entity.getNameEn());
        dto.setKey(entity.getKey());
        dto.setCreatedDate(entity.getCreatedDate());

        return dto;
    }
}
