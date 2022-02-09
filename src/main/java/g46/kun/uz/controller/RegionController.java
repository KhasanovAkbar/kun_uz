package g46.kun.uz.controller;

import g46.kun.uz.dto.RegionDTO;
import g46.kun.uz.service.RegionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/region")
public class RegionController {
    @Autowired
    private RegionService regionService;

    @PostMapping("/create")
    public ResponseEntity<RegionDTO> create(@Valid @RequestBody RegionDTO dto) {
        RegionDTO result = this.regionService.create(dto);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{id}")
    public ResponseEntity<RegionDTO> getById(@PathVariable("id") Integer id) {
        RegionDTO result = this.regionService.getById(id);
        return ResponseEntity.ok(result);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Void> update(@Valid @RequestBody RegionDTO dto, @PathVariable("id") Integer id) {
        this.regionService.update(id, dto);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Integer id) {
        this.regionService.delete(id);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/list")
    public ResponseEntity<List<RegionDTO>> list() {
        List<RegionDTO> list = this.regionService.list();
        return ResponseEntity.ok().body(list);
    }
}
