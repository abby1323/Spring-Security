package com.abby.Security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    //fetch user by email
    Optional<User> findByEmail(String email);

}
