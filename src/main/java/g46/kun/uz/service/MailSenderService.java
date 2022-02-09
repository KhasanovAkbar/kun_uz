package g46.kun.uz.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailSenderService {
    @Autowired
    private JavaMailSender javaMailSender;

    void sendEmail(String toAccount, String subject, String text) {

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(toAccount); // freepik45@gmail.com
        msg.setSubject(subject); //
        msg.setText(text); //
        javaMailSender.send(msg);
    }
}
