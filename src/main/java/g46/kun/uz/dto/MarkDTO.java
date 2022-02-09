package g46.kun.uz.dto;

import g46.kun.uz.types.MarkType;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MarkDTO {

    public Integer id;

    private Integer articleId; //
    private MarkType type;

    private Integer profileId;
    private LocalDateTime createdDate;

    private int likeCount;
    private int dislikeCount;

    private ArticleDTO article;
    private ProfileDTO profile;

    public void setId(Integer id) {
        this.id = id;
    }


}
