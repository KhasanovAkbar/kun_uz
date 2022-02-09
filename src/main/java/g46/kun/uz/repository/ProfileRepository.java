package g46.kun.uz.repository;

import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.types.ProfileStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface ProfileRepository extends JpaRepository<ProfileEntity, Integer>, JpaSpecificationExecutor<ProfileEntity> {

    Optional<ProfileEntity> getByEmail(String email);

    @Transactional
    @Modifying
    @Query("update ProfileEntity set status=:status  where id=:id")
    void updateStatus(@Param("status") ProfileStatus status, @Param("id") Integer id);

    Optional<ProfileEntity> findByEmailAndPassword(String email, String password);

    Optional<ProfileEntity> findByContactAndEmailVC(String contact, String code);

}
