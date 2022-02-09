package g46.kun.uz.converter;

import g46.kun.uz.dto.CommentDTO;
import g46.kun.uz.entity.CommentEntity;

public class CommentConverter {
    public static CommentDTO toDTO(CommentEntity entity) {
        CommentDTO dto = new CommentDTO();
        dto.setId(entity.getId());
        dto.setContent(entity.getContent());
//        dto.setProfileId(entity.getProfile().getId());
        dto.setArticleId(entity.getArticle().getId());
        dto.setCreatedDate(entity.getCreatedDate());

        return dto;
    }
}
