package g46.kun.uz.dto;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.time.LocalDateTime;

@Getter
@Setter
public class CommentDTO {
    private Integer id;

    //    @NotNull
//    private Integer profileId;
    @NotNull
    private Integer articleId;
    @NotBlank
    @Size(min = 10, max = 300)
    private String content;

    private LocalDateTime createdDate;


}
