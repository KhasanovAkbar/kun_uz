package g46.kun.uz.service;

import g46.kun.uz.converter.ArticleConvertor;
import g46.kun.uz.converter.ProfileConverter;
import g46.kun.uz.dto.ArticleDTO;
import g46.kun.uz.dto.MarkDTO;
import g46.kun.uz.dto.ProfileDTO;
import g46.kun.uz.entity.ArticleEntity;
import g46.kun.uz.entity.MarkEntity;
import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.repository.MarkRepository;
import g46.kun.uz.types.MarkType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.swing.plaf.SpinnerUI;
import java.time.LocalDateTime;
import java.util.LinkedList;
import java.util.List;

@Service
public class MarkService {

    @Autowired
    private MarkRepository markRepository;
    @Autowired
    private ProfileService profileService;
    @Autowired
    private ArticleService articleService;

    // like + dislike
    public void create(Integer profileId, MarkDTO markDTO, MarkType martType) {
        ProfileEntity profile = this.profileService.get(profileId);
        ArticleEntity article = this.articleService.get(markDTO.getArticleId());

        MarkEntity old = this.markRepository.findByProfileIdAndArticleId(profileId, markDTO.getArticleId());

        if (old == null) { // create
            MarkEntity markEntity = new MarkEntity();
            markEntity.setArticle(article);
            markEntity.setProfile(profile);
            markEntity.setType(martType);
            markEntity.setCreatedDate(LocalDateTime.now());

            this.markRepository.save(markEntity);
            return;
        }
        // LIKE  == LIKE
        // DISLIKE == DISLIKE
        if (old.getType().equals(martType)) {
            this.markRepository.delete(old);
        } else {
            // LIKE  == DISLIKE
            // DISLIKE == LIKE
            old.setType(martType);
            this.markRepository.save(old);
        }
    }

    public MarkDTO getArticleLikeAndDislikeCount(Integer articleId) {
        int likeCount = this.markRepository.getMarkCount(MarkType.LIKE, articleId);
        int dislikeCount = this.markRepository.getMarkCount(MarkType.DISLIKE, articleId);

        MarkDTO dto = new MarkDTO();
        dto.setLikeCount(likeCount);
        dto.setDislikeCount(dislikeCount);

        return dto;
    }

    // TODO
    public void getProfileLikeAndDislikeCount(Integer articleId) {

    }

    public List<MarkDTO> getProfileLikeArticle(Integer profileId) {
        List<MarkEntity> markEntityList = this.markRepository.findAllByProfileAndType(profileId, MarkType.LIKE);
        List<MarkDTO> dtoList = new LinkedList<>();

        markEntityList.forEach(markEntity -> {
            MarkDTO dto = MarkDTO.builder()
                    .id(markEntity.getId())
                    .articleId(markEntity.getArticle().getId())
                    .type(markEntity.getType())
                    .createdDate(markEntity.getCreatedDate()).build();

            ArticleDTO articleDTO = ArticleConvertor.toDTO(markEntity.getArticle());
            ProfileDTO profileDTO = ProfileConverter.toDTO(markEntity.getProfile());

            dto.setArticle(articleDTO);
            dto.setProfile(profileDTO);

            dtoList.add(dto);

        });

        return dtoList;
    }

    // TODO profile ni like bosgan articlelari
    // TODO profile dislike article
}
