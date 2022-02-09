package g46.kun.uz.converter;

import g46.kun.uz.dto.RegionDTO;
import g46.kun.uz.entity.RegionEntity;

public class RegionConverter {
    public static RegionDTO toDTO(RegionEntity entity) {
        RegionDTO dto = new RegionDTO();
        dto.setId(entity.getId());
        dto.setNameUz(entity.getNameUz());
        dto.setNameRu(entity.getNameRu());
        dto.setNameEn(entity.getNameEn());
        dto.setKey(entity.getKey());
        dto.setCreatedDate(entity.getCreatedDate());

        return dto;
    }
}
