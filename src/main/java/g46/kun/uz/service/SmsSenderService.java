package g46.kun.uz.service;

import com.google.gson.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class SmsSenderService {
    @Value("${sms.api.host}")
    private String apiHost;

    @Value("${sms.api.key}")
    private String key;

    public boolean sendSms(String phone, String message) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("phone", phone);
            jsonObject.addProperty("message", message);
            jsonObject.addProperty("key", key);

            HttpEntity<String> entity = new HttpEntity<>(jsonObject.toString(), headers);
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> response = restTemplate.postForEntity(apiHost, entity, String.class);

            String result = response.getBody();
            System.out.println(result);
            return true;
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
        return false;
    }

}
