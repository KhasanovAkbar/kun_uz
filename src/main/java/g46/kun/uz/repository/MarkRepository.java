package g46.kun.uz.repository;

import g46.kun.uz.entity.ArticleEntity;
import g46.kun.uz.entity.MarkEntity;
import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.types.MarkType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import javax.persistence.criteria.CriteriaBuilder;
import java.util.List;

public interface MarkRepository extends JpaRepository<MarkEntity, Integer> {

    MarkEntity findByProfileAndArticle(ProfileEntity profileEntity, Integer articleId);

    @Query("FROM MarkEntity where article.id =:articleId and profile.id=:profileId")
    MarkEntity findByProfileIdAndArticleId(@Param("articleId") Integer articleId, @Param("profileId") Integer profileId);

    // select count(*) from mark where type = 'LIKE' and article_id = 5
    int countByArticleAndType(ArticleEntity article, MarkType type);

    @Query(" SELECT count(*)  FROM MarkEntity  where type =:type and article.id =:aId")
    int getMarkCount(@Param("type") MarkType type, @Param("aId") Integer articleId);

    @Query("from MarkEntity where profile.id=:id and type=:type")
    List<MarkEntity> findAllByProfileAndType(@Param("id") Integer profileId, @Param("type") MarkType markType);

}
