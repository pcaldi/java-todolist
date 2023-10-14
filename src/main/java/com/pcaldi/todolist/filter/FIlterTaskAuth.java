package com.pcaldi.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pcaldi.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FIlterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Validando se é a rota de /tasks
        var servletPath = request.getServletPath();

        if (servletPath.startsWith("/tasks/")) {
            // Pegar a autenticalçao(usuário e senha)
            var authorization = request.getHeader("Authorization");

            var authEncode = authorization.substring("Basic".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authEncode);

            var authString = new String(authDecode);

            // ["pcaldi", "12345"]
            String[] credatials = authString.split(":");
            String username = credatials[0];
            String password = credatials[1];

            // Validar o usuário
            var user = this.userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401, "Usuário sem autorização.");
            } else {
                // Validar o passaword
                var passawordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

                if (passawordVerify.verified) {
                    // Segue o trecho
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401, "Usuário sem autorização.");
                }

            }
        } else {
            filterChain.doFilter(request, response);
        }

    }

}
