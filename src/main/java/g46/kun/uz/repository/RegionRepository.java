package g46.kun.uz.repository;

import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.entity.RegionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface RegionRepository extends JpaRepository<RegionEntity, Integer> {
    @Transactional
    @Modifying
    @Query("update RegionEntity set visible=false where id =:id")
    int blockRegion(@Param("id") Integer id);

    List<RegionEntity> findAllByVisible(Boolean visible);
}
