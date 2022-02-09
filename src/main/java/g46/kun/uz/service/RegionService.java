package g46.kun.uz.service;

import g46.kun.uz.converter.RegionConverter;
import g46.kun.uz.dto.RegionDTO;
import g46.kun.uz.entity.RegionEntity;
import g46.kun.uz.exp.ItemNotFoundException;
import g46.kun.uz.repository.RegionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class RegionService {
    @Autowired
    private RegionRepository regionRepository;

    public RegionDTO create(RegionDTO dto) {
        RegionEntity entity = new RegionEntity();
        entity.setNameUz(dto.getNameUz());
        entity.setNameRu(dto.getNameRu());
        entity.setNameEn(dto.getNameEn());
        entity.setKey(dto.getKey());
        entity.setCreatedDate(LocalDateTime.now());
        entity.setVisible(true);
        this.regionRepository.save(entity);

        dto.setId(entity.getId());
        dto.setCreatedDate(entity.getCreatedDate());
        return dto;
    }

    public RegionDTO getById(Integer id) {
        return RegionConverter.toDTO(get(id));
    }

    public Boolean update(Integer id, RegionDTO dto) {
        RegionEntity entity = get(id);
        entity.setNameUz(dto.getNameUz());
        entity.setNameRu(dto.getNameRu());
        entity.setNameEn(dto.getNameEn());
        entity.setKey(dto.getKey());

        this.regionRepository.save(entity);
        return true;
    }

    public Boolean delete(Integer id) { // will update status only
        this.regionRepository.blockRegion(id);
        return true;
    }

    public List<RegionDTO> list() {
        return this.regionRepository.findAllByVisible(true)
                .stream()
                .map(RegionConverter::toDTO)
                .collect(Collectors.toList());
    }

    public RegionEntity get(Integer id) {
        return this.regionRepository.findById(id).
                orElseThrow(() -> new ItemNotFoundException("Region not found id+ " + id));
    }

}
