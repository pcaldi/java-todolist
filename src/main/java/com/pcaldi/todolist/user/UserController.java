package com.pcaldi.todolist.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import at.favre.lib.crypto.bcrypt.BCrypt;

@RestController
@RequestMapping("/users")
public class UserController {

    /*
     * String (texto)
     * Integer (int) Números inteiros
     * Double (double) Números 0.000
     * Float (float) Números 0.000
     * Char (A B C)
     * Data (data)
     * void - sem retorno
     * 
     */

    @Autowired
    private IUserRepository userRepository;

    @PostMapping("/")
    public ResponseEntity create(@RequestBody UserModel userModel) {

        var user = this.userRepository.findByUsername(userModel.getUsername());

        if (user != null) {
            // status code
            // mensagem de erro
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Usuário já cadastrado!");
        }

        // Criptografando o password
        var passwordHashred = BCrypt.withDefaults().hashToString(12, userModel.getPassword().toCharArray());
        userModel.setPassword(passwordHashred);

        var userCreated = this.userRepository.save(userModel);
        // status code
        // mensagem de erro
        return ResponseEntity.status(HttpStatus.OK).body(userCreated);

    }

}
