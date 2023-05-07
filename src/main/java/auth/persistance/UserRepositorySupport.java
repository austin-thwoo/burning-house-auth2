//package com.codingfist.burninghouseauth.domain.user.persistance;
//
//import com.codingfist.burninghouseauth.domain.user.domain.User;
//import com.querydsl.jpa.impl.JPAQueryFactory;
//
//import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;
//import org.springframework.stereotype.Repository;
//
//
//import static com.codingfist.burninghouseauth.domain.
//
//@Repository
//public class
//UserRepositorySupport extends QuerydslRepositorySupport {
//
//    private JPAQueryFactory queryFactory;
//
//    public UserRepositorySupport(JPAQueryFactory queryFactory) {
//        super(User.class);
//        this.queryFactory = queryFactory;
//    }
//
//
//    public User findById(Long userId){
//        User result=queryFactory.selectFrom(user)
//                .where(user.id.eq(userId)).fetchOne();
//        if (result ==null){
//            throw new UserNotFoundException(userId.toString());
//        }
//        return result;
//    }
//
//
//    public User findByUserName(String username) {
//        User result = queryFactory.selectFrom(user)
//                .where(user.userName.eq(username)).fetchOne();
//        if (result == null){
//            throw new UserNotFoundException(username);
//        }
//        return result;
//    }
//}
