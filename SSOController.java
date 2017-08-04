
	import java.util.Set;

	import javax.servlet.http.HttpServletRequest;

	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;
	import org.springframework.beans.factory.annotation.Autowired;
	import org.springframework.security.authentication.AnonymousAuthenticationToken;
	import org.springframework.security.core.context.SecurityContextHolder;
	import org.springframework.security.saml.metadata.MetadataManager;
	import org.springframework.stereotype.Controller;
	import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
	import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

	@Controller
	@RequestMapping("/auth")
	public class SSOController {
		
		@Autowired
		private MetadataManager metadata;
		
		@GetMapping("/sso")
		public String idpSelection(HttpServletRequest request, Model model) {
			System.out.println("Debugging Redirect  " + SecurityContextHolder.getContext().getAuthentication());
			if (!(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {
				System.out.println("Inside the sso controller");
				return "redirect:/home";
			} else {
				System.out.println("redirecting");
				return "saml/login";
			}
		}

		/*
		 * Checks if an HTTP request has been forwarded by a servlet.
		 */
		/*private boolean isForwarded(HttpServletRequest request){
			if (request.getAttribute("javax.servlet.forward.request_uri") == null)
				return false;
			else
				return true;
		}
*/
	}

