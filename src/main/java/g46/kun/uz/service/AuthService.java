package g46.kun.uz.service;

import g46.kun.uz.dto.*;
import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.exp.ItemNotFoundException;
import g46.kun.uz.exp.ProfileNotFoundException;
import g46.kun.uz.exp.ServerBadRequestException;
import g46.kun.uz.repository.ProfileRepository;
import g46.kun.uz.types.ProfileRole;
import g46.kun.uz.types.ProfileStatus;
import g46.kun.uz.util.RandomStringUtil;
import g46.kun.uz.util.TokenProcess;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class AuthService {
    @Autowired
    private ProfileRepository profileRepository;
    @Autowired
    private MailSenderService mailSenderService;
    @Autowired
    private SmsSenderService senderService;

    public ProfileDTO auth(AuthorizationDTO dto) {
        String email = dto.getEmail(); // ali@mail.ru
        String pswd = DigestUtils.md5Hex(dto.getPassword()); // abcd123
        Optional<ProfileEntity> optional = this.profileRepository.findByEmailAndPassword(email, pswd);

        if (!optional.isPresent()) {
            throw new ProfileNotFoundException("Login yoki porol xato kiritildi!!!");
        }

        ProfileEntity profileEntity = optional.get();
        if (!profileEntity.getStatus().equals(ProfileStatus.ACTIVE)) {
            throw new ProfileNotFoundException("Profile not Active");
        }

        UserDetails userDetails = new UserDetails();
        userDetails.setId(profileEntity.getId());
        userDetails.setName(profileEntity.getName());
        userDetails.setRole(profileEntity.getRole());

        String jwt = TokenProcess.generateJwt(userDetails);

        ProfileDTO responseDTO = new ProfileDTO();
        responseDTO.setToken(jwt);
        responseDTO.setName(profileEntity.getName());
        responseDTO.setSurname(profileEntity.getSurname());
        responseDTO.setContact(profileEntity.getContact());

        return responseDTO;
    }

    public String registration(RegistrationDTO dto) {
//        String text = String.format(template.getText(), "Bobur", "http://localhost:8085/category/list");

        Optional<ProfileEntity> optional = profileRepository.getByEmail(dto.getEmail());
        if (optional.isPresent()) {
            throw new ServerBadRequestException("Email already exists.");
        }

        ProfileEntity entity = new ProfileEntity();
        entity.setName(dto.getName());
        entity.setSurname(dto.getSurname());
        entity.setEmail(dto.getEmail());
        entity.setContact(dto.getContact());
        entity.setRole(ProfileRole.USER);
        entity.setStatus(ProfileStatus.INACTIVE);
        entity.setCreatedDate(LocalDateTime.now());
        entity.setPassword(DigestUtils.md5Hex(dto.getPassword()));

        String code = RandomStringUtil.generateRandomNumber(5);
        entity.setEmailVC(code);

        this.profileRepository.save(entity);

//        String jwt = TokenProcess.generateJwt(entity.getId());
//        String link = "http://172.20.10.12:8081/auth/verification/" + jwt;

        try {

            senderService.sendSms(entity.getContact(), "kod: " + code);

//            mailSenderService.sendEmail(dto.getEmail(),
//                    "TestKun uz verification",
//                    "Salom jigar shu linkni bos." + link);
        } catch (Exception e) {
            this.profileRepository.delete(entity);
        }

        return "Sizning raqamingizga tasdiqlash kodi yuborildi";
    }

    public String verification(String jwt) {
        Integer profileId = TokenProcess.encodeJwt(jwt);
        Optional<ProfileEntity> optional = this.profileRepository.findById(profileId);
        if (!optional.isPresent()) {
            throw new ItemNotFoundException("Wrong key");
        }
        ProfileEntity profileEntity = optional.get();
        if (!profileEntity.getStatus().equals(ProfileStatus.INACTIVE)) {
            throw new ServerBadRequestException("You are in wrong status");
        }

        profileEntity.setStatus(ProfileStatus.ACTIVE);
        this.profileRepository.save(profileEntity);
        return "Successfully verified";
    }

    public String smsVerification(SmsVerDTO dto) {
        Optional<ProfileEntity> optional = this.profileRepository
                .findByContactAndEmailVC(dto.getContact(), dto.getCode());

        if (!optional.isPresent()) {
            throw new ItemNotFoundException("Wrong key");
        }
        ProfileEntity profileEntity = optional.get();
        if (!profileEntity.getStatus().equals(ProfileStatus.INACTIVE)) {
            throw new ServerBadRequestException("You are in wrong status");
        }

        profileEntity.setStatus(ProfileStatus.ACTIVE);
        this.profileRepository.save(profileEntity);
        return "Successfully verified";

    }
}
