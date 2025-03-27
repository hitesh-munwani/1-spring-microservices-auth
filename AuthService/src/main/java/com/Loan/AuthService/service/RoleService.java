package com.Loan.AuthService.service;

import com.Loan.AuthService.model.Role;
import com.Loan.AuthService.repository.RoleRepo;
import org.springframework.beans.factory.annotation.Autowired;

public class RoleService {

    @Autowired
    public RoleRepo roleRepo;

    public Role findByName(String name) {
        return roleRepo.findByName(name);
    }
    //create a new role


}
