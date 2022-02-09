package g46.kun.uz.repository.impl;

import g46.kun.uz.dto.FilterDTO;
import g46.kun.uz.entity.ProfileEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;

@Repository
public class ProfileCustomRepository {

    @Autowired
    private EntityManager entityManager;

    public void filterJon(FilterDTO dto) {

        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<ProfileEntity> criteriaQuery = criteriaBuilder.createQuery(ProfileEntity.class);

        Root<ProfileEntity> root = criteriaQuery.from(ProfileEntity.class);
        criteriaQuery.select(root); // select from ProfileEntity

        ArrayList<Predicate> predicateList = new ArrayList<>();
        if (dto.getName() != null) {
            predicateList.add(criteriaBuilder.equal(root.get("name"), dto.getName()));
        }
        if (dto.getNameList() != null) {
//            CriteriaBuilder.In<String> inClause = criteriaBuilder.in(root.get("name")); // .in(dto.getNameList())); // name in (.......)
            predicateList.add(criteriaBuilder.and(root.get("name").in(dto.getNameList())));
        }
        if (dto.getSurname() != null) {
            predicateList.add(criteriaBuilder.equal(root.get("surname"), dto.getSurname()));
        }
        if (dto.getEmail() != null) {
            predicateList.add(criteriaBuilder.equal(root.get("email"), dto.getEmail()));
        }
        if (dto.getContact() != null) {
            predicateList.add(criteriaBuilder.equal(root.get("contact"), dto.getContact()));
        }


        Predicate[] predicateArray = new Predicate[predicateList.size()];
        predicateList.toArray(predicateArray);

        criteriaQuery.where(predicateArray);

        List<ProfileEntity> profileEntityList = entityManager.createQuery(criteriaQuery).getResultList();

        profileEntityList.forEach(profileEntity -> {
            System.out.println(profileEntity.getName());
        });
    }


    //        Predicate namePredicate = criteriaBuilder.equal(root.get("name"), "111"); // name = 'Bobur'
//        Predicate surnamePredicate = criteriaBuilder.like(root.get("surname"), "1111"); // surname = 'Boburjon'
//        Predicate emailPredicate = criteriaBuilder.equal(root.get("email"),"bigmangcom@gmail.com"); // email is not null
//        Predicate nameOrSurname =  criteriaBuilder.or(namePredicate, surnamePredicate,emailPredicate); // 1 or 2 or 3
//        Predicate nameAndSurname =  criteriaBuilder.and(namePredicate,surnamePredicate,emailPredicate); // 1 and 2 and 3
    // (name =:name and surname=:surname) or email not null
//        Predicate nameAndSurname =  criteriaBuilder.and(namePredicate,surnamePredicate);
//        Predicate orEmail = criteriaBuilder.or(nameAndSurname,emailPredicate);
//        criteriaQuery.where(orEmail);
    // where  name = 'Bobur' and surname like 'B%'

}
