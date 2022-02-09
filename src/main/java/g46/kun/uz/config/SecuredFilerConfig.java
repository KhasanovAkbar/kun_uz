package g46.kun.uz.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecuredFilerConfig {

    @Autowired
    private JwtTokenFilter jwtTokenFilter;

    @Bean
    public FilterRegistrationBean filterRegistrationBean() {

        FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setFilter(jwtTokenFilter);
//        bean.addUrlPatterns("/profile/*");
        bean.addUrlPatterns("/article/list/*");
        bean.addUrlPatterns("/mark/*");
        bean.addUrlPatterns("/comment/secure/**");
        // TODO article, profile,
        return bean;
    }

}
