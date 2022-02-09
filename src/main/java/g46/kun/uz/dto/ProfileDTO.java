package g46.kun.uz.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import g46.kun.uz.types.ProfileRole;
import g46.kun.uz.types.ProfileStatus;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.*;
import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class ProfileDTO {
    private Integer id;

    @NotEmpty(message = "Please provide a name")
    private String name;
    @NotBlank(message = "Please provide a surname")
    private String surname;
    @Email(message = "Voy email xatoku")
    private String email;
    @NotEmpty(message = "Please provide a contact")
    private String contact;
    @NotNull
    private ProfileStatus status;
    @NotBlank(message = "Please provide a  password")
    @Size(min = 5, max = 15, message = "15 dan ko'p bo'lsa esingdan chiqadiku.")
    private String password;
    @NotNull
    private ProfileRole role;

    private LocalDateTime createdDate;
    private String token;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getContact() {
        return contact;
    }

    public void setContact(String contact) {
        this.contact = contact;
    }

    public ProfileStatus getStatus() {
        return status;
    }

    public void setStatus(ProfileStatus status) {
        this.status = status;
    }

    public ProfileRole getRole() {
        return role;
    }

    public void setRole(ProfileRole role) {
        this.role = role;
    }

    public LocalDateTime getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(LocalDateTime createdDate) {
        this.createdDate = createdDate;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
