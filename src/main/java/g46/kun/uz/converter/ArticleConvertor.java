package g46.kun.uz.converter;

import g46.kun.uz.dto.ArticleDTO;
import g46.kun.uz.entity.ArticleEntity;

public class ArticleConvertor {
    public static ArticleDTO toDTO(ArticleEntity entity) {
        ArticleDTO dto = new ArticleDTO();
        dto.setId(entity.getId());
        dto.setTitle(entity.getTitle());
        dto.setContent(entity.getContent());
        dto.setStatus(entity.getStatus());

        dto.setCategoryId(entity.getCategory().getId());
        dto.setRegionId(entity.getRegion().getId());
        dto.setProfileId(entity.getProfile().getId());

        dto.setToken(entity.getToken());
        dto.setViewCount(entity.getViewCount());

        dto.setCreatedDate(entity.getCreatedDate());
        dto.setPublishDate(entity.getPublishDate());

        return dto;
    }
}
