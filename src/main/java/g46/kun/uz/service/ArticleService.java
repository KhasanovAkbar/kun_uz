package g46.kun.uz.service;

import g46.kun.uz.converter.ArticleConvertor;
import g46.kun.uz.dto.ArticleDTO;
import g46.kun.uz.dto.ArticleFilterDTO;
import g46.kun.uz.dto.MarkDTO;
import g46.kun.uz.entity.ArticleEntity;
import g46.kun.uz.entity.CategoryEntity;
import g46.kun.uz.entity.ProfileEntity;
import g46.kun.uz.entity.RegionEntity;
import g46.kun.uz.exp.ItemNotFoundException;
import g46.kun.uz.repository.ArticleRepository;
import g46.kun.uz.repository.ProfileRepository;
import g46.kun.uz.types.ArticleStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class ArticleService {
    @Autowired
    private ArticleRepository articleRepository;
    @Autowired
    private ProfileService profileService;
    @Autowired
    private CategoryService categoryService;
    @Autowired
    private RegionService regionService;
    @Autowired
    private ProfileRepository profileRepository;
    @Autowired
    private MarkService markService;

    public ArticleDTO create(ArticleDTO dto) {

        RegionEntity region = this.regionService.get(dto.getRegionId());
        CategoryEntity category = this.categoryService.get(dto.getCategoryId());
        ProfileEntity profile = this.profileService.get(dto.getProfileId());


        ArticleEntity entity = new ArticleEntity();
        entity.setTitle(dto.getTitle());
        entity.setContent(dto.getContent());
        entity.setStatus(ArticleStatus.CREATED);

        entity.setCategory(category);
        entity.setRegion(region);
        entity.setProfile(profile);

        entity.setToken(UUID.randomUUID().toString());
        entity.setCreatedDate(LocalDateTime.now());

        this.articleRepository.save(entity);

        dto.setId(entity.getId());
        dto.setStatus(ArticleStatus.CREATED);
        dto.setToken(entity.getToken());
        dto.setViewCount(0);
        dto.setCreatedDate(entity.getCreatedDate());

        return dto;
    }

    public ArticleDTO getById(Integer id) {
        ArticleEntity articleEntity = get(id);
        ArticleDTO dto = ArticleConvertor.toDTO(articleEntity);

        MarkDTO markDTO = markService.getArticleLikeAndDislikeCount(id);
        dto.setMarkDTO(markDTO);

        //TODO commentlar soni???????

        return dto;
    }

    public Boolean update(Integer id, ArticleDTO dto) {
        ArticleEntity article = get(id);

        RegionEntity region = this.regionService.get(dto.getRegionId());
        CategoryEntity category = this.categoryService.get(dto.getCategoryId());

        article.setTitle(dto.getTitle());
        article.setContent(dto.getContent());
        article.setStatus(ArticleStatus.UPDATED);

        article.setCategory(category);
        article.setRegion(region);

        this.articleRepository.save(article);

        return true;
    }

    public Boolean publish(Integer id) {
        this.articleRepository.publishArticle(id, ArticleStatus.PUBLISHED, LocalDateTime.now());
        return true;
    }

    public Boolean block(Integer id) {
        this.articleRepository.blockArticle(id, ArticleStatus.BLOCKED);
        return true;
    }

    public Page<ArticleDTO> list(int page, int size) {
//        Pageable paging = PageRequest.of(page, size, Sort.by("createdDate").descending());
//        return this.articleRepository.findAll(paging).stream().map(ArticleConvertor::toDTO).collect(Collectors.toList());
        Pageable pageable = PageRequest.of(page, size);
        Page<ArticleEntity> paging = this.articleRepository.findAll(pageable);

        int totalPage = paging.getTotalPages();
        long totalElements = paging.getTotalElements();
        int currentPage = paging.getNumber();
        List<ArticleEntity> articleEntityList = paging.getContent();

        System.out.println("totalPage: " + totalPage);
        System.out.println("totalElements: " + totalElements);
        System.out.println("currentPage: " + currentPage);

        List<ArticleDTO> dtoList = articleEntityList.stream().map(ArticleConvertor::toDTO).collect(Collectors.toList());

        Page<ArticleDTO> resultPage = new PageImpl(dtoList, pageable, totalElements);

        return resultPage;
    }

    public Page<ArticleDTO> listByProfile(Integer profileId, int page, int size) {
        ProfileEntity profileEntity = this.profileService.get(profileId);

        Pageable pageable = PageRequest.of(page, size);

//        Page<ArticleEntity> paging = this.articleRepository.findByProfile(profileEntity, pageable);
        Page<ArticleEntity> paging = this.articleRepository.getArticleByProfileId(profileId, pageable);

        List<ArticleDTO> dtoList = paging.getContent().stream()
                .map(ArticleConvertor::toDTO)
                .collect(Collectors.toList());

        return new PageImpl<>(dtoList, pageable, paging.getTotalElements());
    }

    public Page<ArticleDTO> listByCategory(Integer categoryId, int page, int size) {
        Sort sort = Sort.by("createdDate").descending();
        CategoryEntity categoryEntity = this.categoryService.get(categoryId);
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<ArticleEntity> paging = this.articleRepository.findByCategoryAndStatus(categoryEntity, ArticleStatus.PUBLISHED, pageable);

        List<ArticleDTO> dtoList = paging.getContent().stream().map(ArticleConvertor::toDTO).collect(Collectors.toList());
        return new PageImpl<>(dtoList, pageable, paging.getTotalElements());
    }

    public List<ArticleDTO> listByRegion(Integer regionId, int page, int size) {
        Pageable paging = PageRequest.of(page, size, Sort.by("createdDate").descending());

        List<ArticleEntity> articleList = this.articleRepository.findByRegionId(regionId, paging);
        return articleList.stream().map(ArticleConvertor::toDTO).collect(Collectors.toList());
    }

    public Page<ArticleDTO> filter(ArticleFilterDTO filter) {
        return null;
    }

    // oxirgi qo'shilgan 8tasi
    public List<ArticleDTO> lastAdded() {
        Pageable paging = PageRequest.of(0, 8, Sort.by("createdDate").descending());
        List<ArticleEntity> articleList = this.articleRepository.findByStatus(ArticleStatus.PUBLISHED, paging);

        return articleList.stream().map(ArticleConvertor::toDTO).collect(Collectors.toList());
    }

    // ko'p o'qilganlar oxirgi 8tasi
    public List<ArticleDTO> last8() {

        Sort sort = Sort.by(Sort.Direction.DESC, "createdDate");

//        List<ArticleEntity> entityList = this.articleRepository.findTop8ByOrderByCreatedDateDesc();
        List<ArticleEntity> entityList = this.articleRepository.findTop8By(sort);


        return entityList.stream().map(ArticleConvertor::toDTO).collect(Collectors.toList());
    }

    // dolzarb oxirgi 4tasi
    public List<ArticleDTO> popular() {
        return null;
    }

    // kategoriya bo'yicha eng oxirgi yangiliklar
    public List<ArticleDTO> lastPublishedByCategory() {
        return null;
    }

    // region bo'yicha eng oxirgi yangiliklar
    public List<ArticleDTO> lastPublishedByRegion() {
        return null;
    }

    public List<ArticleDTO> getAll() {

        Sort sortByTitle = Sort.by("title").descending();

        Sort sort = Sort.by(Sort.Direction.ASC, "id").and(sortByTitle);

        this.articleRepository.findAll(sort);
        return null;
    }

    public ArticleEntity get(Integer id) {
        return this.articleRepository.findById(id).orElseThrow(() -> new ItemNotFoundException("Article not found" + id));
    }
}
