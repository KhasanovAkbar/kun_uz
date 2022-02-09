package g46.kun.uz.controller;

import g46.kun.uz.dto.FilterDTO;
import g46.kun.uz.dto.ProfileDTO;
import g46.kun.uz.dto.ProfileFilterDTO;
import g46.kun.uz.dto.UserDetails;
import g46.kun.uz.exp.ServerBadRequestException;
import g46.kun.uz.service.ProfileService;
import g46.kun.uz.types.ProfileStatus;
import g46.kun.uz.util.TokenProcess;
import g46.kun.uz.util.TokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/profile")
public class ProfileController {
    @Autowired
    private ProfileService profileService;

    @PostMapping("/create")
    public ResponseEntity<?> create(@Valid @RequestBody ProfileDTO dto) {
        try {
            ProfileDTO result = this.profileService.create(dto);
            return ResponseEntity.ok(result);
        } catch (ServerBadRequestException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (RuntimeException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable("id") Integer id, HttpServletRequest request) {
        UserDetails userDetails = TokenUtil.getCurrentUser(request);

        ProfileDTO profileDTO = this.profileService.getById(id);
        return new ResponseEntity<>(profileDTO, HttpStatus.OK);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@Valid @RequestBody ProfileDTO dto, @PathVariable("id") Integer id) {
        this.profileService.update(id, dto);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PutMapping("/{id}/status/{status}")
    public ResponseEntity<Void> changeStatus(@PathVariable("id") Integer id, @PathVariable("status") ProfileStatus status) {
        this.profileService.changeStatus(id, status);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/list")
    public ResponseEntity<List<ProfileDTO>> getList() {
        List<ProfileDTO> list = this.profileService.getList();
        return ResponseEntity.ok(list);
    }

    @GetMapping("/paging")
    public ResponseEntity<Page<ProfileDTO>> getList(@RequestParam("page") Integer page, @RequestParam("size") Integer size) {
        Page<ProfileDTO> list = this.profileService.getListForPagination(page, size);
        return ResponseEntity.ok(list);
    }

    @PostMapping("/filter")
    public ResponseEntity<List<ProfileDTO>> filtering(@RequestBody ProfileFilterDTO filter) {
        List<ProfileDTO> list = this.profileService.filter(filter);
        return ResponseEntity.ok(list);
    }


    @PostMapping("/testjon")
    public ResponseEntity<?> filtering(@RequestBody FilterDTO dto) {
        this.profileService.testJon(dto);
        return ResponseEntity.ok().build();
    }


}
