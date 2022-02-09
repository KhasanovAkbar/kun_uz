package g46.kun.uz.util;

import g46.kun.uz.dto.UserDetails;

import javax.servlet.http.HttpServletRequest;

public class TokenUtil {
    public static UserDetails getCurrentUser(HttpServletRequest request) throws RuntimeException {

        UserDetails currentUser = (UserDetails) request.getAttribute("currentUser");

        if (currentUser == null) {
            throw new RuntimeException("METHOD NOT ALLOWED");
        }
        return currentUser;
    }
}
