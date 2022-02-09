package g46.kun.uz.dto;

import g46.kun.uz.types.ArticleStatus;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

@Getter
@Setter
public class ArticleDTO {
    private Integer id;

    @NotBlank
    private String title;
    @NotBlank
    private String content;
    @NotNull
    private Integer profileId; //
    @NotNull
    private Integer regionId;
    @NotNull
    private Integer categoryId;

    private ArticleStatus status;
    private String token;
    private Integer viewCount;
    private LocalDateTime createdDate;
    private LocalDateTime publishDate;

    private MarkDTO markDTO;
}
