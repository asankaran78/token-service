package com.security;

import org.springframework.security.core.Authentication;
import javax.servlet.http.HttpServletRequest;

import io.jsonwebtoken.Jwts;

public class TokenAuthenticationService {
	    private String secret = "ThisIsASecret";
	    private String headerString = "Authorization";


	    public Authentication getAuthentication(HttpServletRequest request)
	    {
	        String token = request.getHeader(headerString);
	        if(token != null)
	        {
	            // parse the token.
	            String username = Jwts.parser()
	                        .setSigningKey(secret)
	                        .parseClaimsJws(token)
	                        .getBody()
	                        .getSubject();
	            if(username.contains("admin")) // we managed to retrieve a user
	            {
	                return new AuthenticatedUser(username);
	            }
	        }
	        return null;
	    }
}

