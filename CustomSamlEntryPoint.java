

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.stereotype.Component;


public class CustomSamlEntryPoint extends SAMLEntryPoint {
	 
	  @Override
	  public void commence(HttpServletRequest request, HttpServletResponse response,
	                       AuthenticationException e) throws IOException, ServletException {
	    if (isXmlHttpRequest(request) && e instanceof InsufficientAuthenticationException) {
		    System.out.print("Inside if condition");
	    	e.printStackTrace();
	      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
	      return;
	    }
	    //System.out.print("Before calling super.commence");
	    super.commence(request, response, e);
	  }
	 
	  private boolean isXmlHttpRequest(HttpServletRequest request) {
	    return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
	  }
	}
