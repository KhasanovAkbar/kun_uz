package g46.kun.uz.repository;

import g46.kun.uz.entity.ArticleEntity;
import g46.kun.uz.entity.CommentEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CommentRepository extends JpaRepository<CommentEntity, Integer> {

    List<CommentEntity> findByArticle(ArticleEntity article, Pageable pageable);

    @Query("FROM CommentEntity where profile.id =:id")
    List<CommentEntity> findByProfileId(@Param("id") Integer profileId, Pageable pageable);
}
