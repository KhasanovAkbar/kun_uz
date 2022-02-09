package g46.kun.uz.service;

import g46.kun.uz.converter.CategoryConverter;
import g46.kun.uz.dto.CategoryDTO;
import g46.kun.uz.entity.CategoryEntity;
import g46.kun.uz.exp.ItemNotFoundException;
import g46.kun.uz.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CategoryService {

    @Autowired
    private CategoryRepository categoryRepository;

    public CategoryDTO create(CategoryDTO dto) {
        CategoryEntity entity = new CategoryEntity();
        entity.setNameUz(dto.getNameUz());
        entity.setNameRu(dto.getNameRu());
        entity.setNameEn(dto.getNameEn());
        entity.setKey(dto.getKey());
        entity.setCreatedDate(LocalDateTime.now());
        entity.setVisible(true);
        this.categoryRepository.save(entity);

        dto.setId(entity.getId());
        dto.setCreatedDate(entity.getCreatedDate());
        return dto;
    }

    public CategoryDTO getById(Integer id) {
        return CategoryConverter.toDTO(get(id));
    }

    public Boolean update(Integer id, CategoryDTO dto) {
        CategoryEntity entity = get(id);
        entity.setNameUz(dto.getNameUz());
        entity.setNameRu(dto.getNameRu());
        entity.setNameEn(dto.getNameEn());
        entity.setKey(dto.getKey());

        this.categoryRepository.save(entity);
        return true;
    }

    // will update status only
    public Boolean delete(Integer id) {
        this.categoryRepository.blockCategory(id);
        return true;
    }

    public List<CategoryDTO> list() {
        return this.categoryRepository.findAll().stream().map(CategoryConverter::toDTO).collect(Collectors.toList());
    }

    public CategoryEntity get(Integer id) {
        return this.categoryRepository.findById(id).orElseThrow(() -> new ItemNotFoundException("Category not found id+ " + id));
    }
}
