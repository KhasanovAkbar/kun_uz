package g46.kun.uz.controller;

import g46.kun.uz.dto.CommentDTO;
import g46.kun.uz.service.CommentService;
import g46.kun.uz.util.TokenProcess;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/comment")
public class CommentController {
    @Autowired
    private CommentService commentService;

    @PostMapping("/secure/create")
    public ResponseEntity<CommentDTO> create(@Valid @RequestBody CommentDTO dto,
                                             @RequestHeader("Authorization") String jwt) {

        Integer profileId = TokenProcess.encodeJwt(jwt);
        CommentDTO result = this.commentService.create(dto, profileId);
        return ResponseEntity.ok(result);
    }


    @GetMapping("/secure/{id}")
    public ResponseEntity<CommentDTO> getById(@PathVariable("id") Integer id) {
        CommentDTO result = this.commentService.getById(id);
        return ResponseEntity.ok(result);
    }

    @PutMapping("/secure/{id}")
    public ResponseEntity<CommentDTO> update(@Valid @RequestBody CommentDTO dto, @PathVariable("id") Integer id) {
        this.commentService.update(id, dto);
        return ResponseEntity.ok().build();
    }


    @GetMapping("/secure/list")
    public ResponseEntity<List<CommentDTO>> list(@RequestParam("size") Integer size,
                                                 @RequestParam("page") Integer page) {
        List<CommentDTO> list = this.commentService.list(page, size);
        return ResponseEntity.ok().body(list);
    }

    @DeleteMapping("/secure/{id}")
    public ResponseEntity<CommentDTO> delete(@PathVariable("id") Integer id) {
        this.commentService.delete(id);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/article/{id}")
    public ResponseEntity<List<CommentDTO>> listByArticle(@PathVariable("id") Integer id,
                                                          @RequestParam("size") Integer size,
                                                          @RequestParam("page") Integer page) {
        List<CommentDTO> list = this.commentService.getListByArticleId(id, page, size);
        return ResponseEntity.ok().body(list);
    }

    @GetMapping("/secure/profile/{id}")
    public ResponseEntity<List<CommentDTO>> listByProfile(@PathVariable("id") Integer id,
                                                          @RequestParam("size") Integer size,
                                                          @RequestParam("page") Integer page) {
        List<CommentDTO> list = this.commentService.getListByProfile(id, page, size);
        return ResponseEntity.ok().body(list);
    }
}
