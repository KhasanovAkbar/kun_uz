package g46.kun.uz.config;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;

@Configuration
public class EmailConfig {

    @Bean
    public SimpleMailMessage templateSimpleMessage() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText(
                "Assalomu alaykum Xurmatli: %s.\n Sizni KunUz jamosi taqdirlaydi.\n" +
                        " Registratsiyani tugatish uchun quyidagi linkni bosing: %s");
        return message;
    }
}
