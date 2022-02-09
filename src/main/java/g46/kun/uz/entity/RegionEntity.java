package g46.kun.uz.entity;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "region")
public class RegionEntity {
    // Toshkent, Qoraqalpog‘iston, Andijon, Farg‘ona, Namangan, Samarqand, Buxoro, Xorazm, Surxondaryo
    //Qashqadaryo, Jizzax, Sirdaryo, Toshkent vil., Navoiy
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(name = "name_uz")
    private String nameUz;
    @Column(name = "name_ru")
    private String nameRu;
    @Column(name = "name_en")
    private String nameEn;
    @Column(name = "key")
    private String key;
    @Column(name = "visible")
    private Boolean visible;
    @Column(name = "created_date")
    private LocalDateTime createdDate;
}
