package g46.kun.uz.repository;

import g46.kun.uz.entity.ArticleEntity;
import g46.kun.uz.entity.CategoryEntity;
import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.types.ArticleStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

public interface ArticleRepository extends JpaRepository<ArticleEntity, Integer> {
    @Transactional
    @Modifying
    @Query("update ArticleEntity set status=:status,  publishDate =:publishDate where id =:id")
    int publishArticle(@Param("id") Integer id, @Param("status") ArticleStatus status, @Param("publishDate") LocalDateTime publishDate);

    @Transactional
    @Modifying
    @Query("update ArticleEntity set status=:status where id =:id")
    int blockArticle(@Param("id") Integer id, @Param("status") ArticleStatus status);

    Page<ArticleEntity> findByProfile(ProfileEntity profile, Pageable pageable);

    @Query(value = "select * from article where profile_id =:id", nativeQuery = true)
    Page<ArticleEntity> getArticleByProfileId(@Param("id") Integer id, Pageable pageable);

    Page<ArticleEntity> findByCategoryAndStatus(CategoryEntity category, ArticleStatus status, Pageable pageable);

    @Query("FROM ArticleEntity where category.id =:categoryId")
    List<ArticleEntity> findByCategoryId(@Param("categoryId") Integer categoryId, Pageable pageable);

    @Query("FROM ArticleEntity where region.id =:regionId")
    List<ArticleEntity> findByRegionId(@Param("regionId") Integer regionId, Pageable pageable);

    List<ArticleEntity> findByStatus(ArticleStatus status, Pageable pageable);

    List<ArticleEntity> findTop8ByOrderByCreatedDateDesc();

    List<ArticleEntity> findTop8By(Sort sort);

}
