package g46.kun.uz.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class FilterDTO {
    private String name;
    private String surname;
    private String email;
    private String contact;
    private List<String> nameList;

}
