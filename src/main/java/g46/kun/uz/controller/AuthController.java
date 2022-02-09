package g46.kun.uz.controller;

import g46.kun.uz.dto.AuthorizationDTO;
import g46.kun.uz.dto.ProfileDTO;
import g46.kun.uz.dto.RegistrationDTO;
import g46.kun.uz.dto.SmsVerDTO;
import g46.kun.uz.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/authorization")
    public ResponseEntity<?> auth(@Valid @RequestBody AuthorizationDTO dto) {
        System.out.println("Authorization: {} " + dto);
        ProfileDTO result = this.authService.auth(dto);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/registration")
    public ResponseEntity<?> registration(@Valid @RequestBody RegistrationDTO dto) {
        System.out.println("Registration: {} " + dto);
        String result = this.authService.registration(dto);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/verification/{jwt}")
    public ResponseEntity<?> registration(@PathVariable("jwt") String jwt) {
        System.out.println("verification: jwt " + jwt);
        String result = this.authService.verification(jwt);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/sms/verification")
    public ResponseEntity<?> smsVerification(@RequestBody SmsVerDTO dto) {
        String result = this.authService.smsVerification(dto);
        return ResponseEntity.ok(result);
    }
}
