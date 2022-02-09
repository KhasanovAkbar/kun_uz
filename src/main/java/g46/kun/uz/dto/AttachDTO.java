package g46.kun.uz.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AttachDTO {
    private String id;

    private String url;

    private String fileName;
    private String path;
    private String originalName;

    private long size;
    private String contentType;


    public AttachDTO() {
    }
}
