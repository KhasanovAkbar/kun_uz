package g46.kun.uz.dto;

import g46.kun.uz.types.ProfileRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserDetails {
    private Integer id;
    private String name;
    private ProfileRole role;
}
