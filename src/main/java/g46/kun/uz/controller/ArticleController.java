package g46.kun.uz.controller;


import g46.kun.uz.dto.ArticleDTO;
import g46.kun.uz.dto.CategoryDTO;
import g46.kun.uz.dto.UserDetails;
import g46.kun.uz.service.ArticleService;
import g46.kun.uz.util.TokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/article")
public class ArticleController {
    @Autowired
    private ArticleService articleService;

    // TODO   jwt
    @PostMapping("/create")
    public ResponseEntity<ArticleDTO> create(@Valid @RequestBody ArticleDTO dto) {
        ArticleDTO result = this.articleService.create(dto);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ArticleDTO> getById(@PathVariable("id") Integer id) {
        ArticleDTO result = this.articleService.getById(id);
        return ResponseEntity.ok(result);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Void> update(@Valid @RequestBody ArticleDTO dto, @PathVariable("id") Integer id) {
        this.articleService.update(id, dto);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/{id}/publish")
    public ResponseEntity<Void> publish(@PathVariable("id") Integer id) {
        this.articleService.publish(id);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/{id}/block")
    public ResponseEntity<Void> block(@PathVariable("id") Integer id) {
        this.articleService.block(id);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/list")
    public ResponseEntity<Page<ArticleDTO>> list(@RequestParam("page") Integer page,
                                                 @RequestParam("size") Integer size, HttpServletRequest request) {
        UserDetails userDetails = TokenUtil.getCurrentUser(request);

        Page<ArticleDTO> list = this.articleService.list(page, size);
        return ResponseEntity.ok().body(list);
    }


    @GetMapping("/list/profile/{id}")
    public ResponseEntity<Page<ArticleDTO>> listByProfile(@PathVariable("id") Integer id,
                                                          @RequestParam(value = "page", defaultValue = "0") Integer page,
                                                          @RequestParam(value = "size", defaultValue = "10") Integer size) {
        Page<ArticleDTO> list = this.articleService.listByProfile(id, page, size);
        return ResponseEntity.ok().body(list);
    }

    @GetMapping("/list/category/{id}")
    public ResponseEntity<Page<ArticleDTO>> listByCategory(@PathVariable("id") Integer id,
                                                           @RequestParam(value = "page", defaultValue = "0") Integer page,
                                                           @RequestParam(value = "size", defaultValue = "10") Integer size) {
        Page<ArticleDTO> list = this.articleService.listByCategory(id, page, size);
        return ResponseEntity.ok().body(list);
    }

    @GetMapping("/list/region/{id}")
    public ResponseEntity<List<ArticleDTO>> listByRegion(@PathVariable("id") Integer id,
                                                         @RequestParam(value = "page", defaultValue = "0") Integer page,
                                                         @RequestParam(value = "size", defaultValue = "10") Integer size) {
        List<ArticleDTO> list = this.articleService.listByRegion(id, page, size);
        return ResponseEntity.ok().body(list);
    }


    @GetMapping("/list/last8")
    public ResponseEntity<List<ArticleDTO>> last8() {
        List<ArticleDTO> list = this.articleService.last8();
        return ResponseEntity.ok().body(list);
    }

}
