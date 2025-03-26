package com.Loan.AuthService.Service;

import com.Loan.AuthService.Model.Role;
import com.Loan.AuthService.Repository.RoleRepo;
import org.springframework.beans.factory.annotation.Autowired;

public class RoleService {

    @Autowired
    public RoleRepo roleRepo;

    public Role findByName(String name) {
        return roleRepo.findByName(name);
    }
    //create a new role


}
