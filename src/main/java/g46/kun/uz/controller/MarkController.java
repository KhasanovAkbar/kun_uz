package g46.kun.uz.controller;

import g46.kun.uz.dto.MarkDTO;
import g46.kun.uz.dto.UserDetails;
import g46.kun.uz.service.MarkService;
import g46.kun.uz.types.MarkType;
import g46.kun.uz.util.TokenProcess;
import g46.kun.uz.util.TokenUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.persistence.criteria.CriteriaBuilder;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/mark")
public class MarkController {
    @Autowired
    private MarkService markService;

    @PostMapping("/like")
    public ResponseEntity<MarkDTO> like(@Valid @RequestBody MarkDTO dto, HttpServletRequest request) {
        UserDetails userDetails = TokenUtil.getCurrentUser(request);
        this.markService.create(userDetails.getId(), dto, MarkType.LIKE);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/dislike")
    public ResponseEntity<MarkDTO> dislike(@Valid @RequestBody MarkDTO dto, HttpServletRequest request) {
        UserDetails userDetails = TokenUtil.getCurrentUser(request);
        this.markService.create(userDetails.getId(), dto, MarkType.DISLIKE);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/profile/like")
    public ResponseEntity<List<MarkDTO>> getProfileLikeArticle(HttpServletRequest request) {
        UserDetails userDetails = TokenUtil.getCurrentUser(request);
        List<MarkDTO> dtoList = this.markService.getProfileLikeArticle(userDetails.getId());
        return ResponseEntity.ok().body(dtoList);
    }
}
