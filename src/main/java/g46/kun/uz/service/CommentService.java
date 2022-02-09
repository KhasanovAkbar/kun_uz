package g46.kun.uz.service;

import g46.kun.uz.converter.CommentConverter;
import g46.kun.uz.dto.ArticleFilterDTO;
import g46.kun.uz.dto.CommentDTO;
import g46.kun.uz.entity.ArticleEntity;
import g46.kun.uz.entity.CommentEntity;
import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.exp.ItemNotFoundException;
import g46.kun.uz.repository.CommentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CommentService {
    @Autowired
    private CommentRepository commentRepository;
    @Autowired
    private ProfileService profileService;
    @Autowired
    private ArticleService articleService;

    public CommentDTO create(CommentDTO dto, Integer profileId) {

        ProfileEntity profile = profileService.get(profileId);
        ArticleEntity article = articleService.get(dto.getArticleId());

        CommentEntity entity = new CommentEntity();
        entity.setContent(dto.getContent());
        entity.setProfile(profile);
        entity.setArticle(article);
        entity.setCreatedDate(LocalDateTime.now());

        this.commentRepository.save(entity);
        dto.setId(entity.getId());
        return dto;
    }

    public CommentDTO getById(Integer id) {
        return CommentConverter.toDTO(get(id));
    }

    public Boolean update(Integer id, CommentDTO dto) {
        CommentEntity entity = get(id);
        entity.setContent(dto.getContent());
        this.commentRepository.save(entity);
        return true;
    }

    public List<CommentDTO> list(int page, int size) {
        Pageable paging = PageRequest.of(page, size, Sort.by("createdDate").descending());

        List<CommentEntity> list = this.commentRepository.findAll();
        return list.stream().map(entity -> CommentConverter.toDTO(entity)).collect(Collectors.toList());
    }

    public List<CommentDTO> filter(ArticleFilterDTO dto) {
        return null;
    }

    public Boolean delete(Integer id) {
        CommentEntity entity = get(id);
        this.commentRepository.delete(entity);
        return true;
    }

    public List<CommentDTO> getListByArticleId(Integer articleId, int page, int size) {
        Pageable paging = PageRequest.of(page, size, Sort.by("createdDate").descending());

        ArticleEntity articleEntity = this.articleService.get(articleId);
        List<CommentEntity> list = this.commentRepository.findByArticle(articleEntity, paging);

        return list.stream().map(entity -> CommentConverter.toDTO(entity)).collect(Collectors.toList());
    }

    public List<CommentDTO> getListByProfile(Integer profileId, int page, int size) {
        Pageable paging = PageRequest.of(page, size, Sort.by("createdDate").descending());

        List<CommentEntity> list = this.commentRepository.findByProfileId(profileId, paging);
        return list.stream().map(entity -> CommentConverter.toDTO(entity)).collect(Collectors.toList());
    }

    public CommentEntity get(Integer id) {
        return this.commentRepository.findById(id).orElseThrow(() -> new ItemNotFoundException("Comment not found id: " + id));
    }
}
