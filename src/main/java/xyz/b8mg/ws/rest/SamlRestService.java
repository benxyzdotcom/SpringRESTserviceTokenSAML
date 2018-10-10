package xyz.b8mg.ws.rest;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;


import xyz.b8mg.bean.TokenBean;
import xyz.b8mg.services.TokenSamlService;
import xyz.b8mg.services.impl.TokenSamlServiceImpl;

@RestController
@RequestMapping("/v1")
public class SamlRestService {

	
	@RequestMapping(value= "/token", produces = MediaType.APPLICATION_XML_VALUE)
	public TokenBean getTokenTest() throws Exception {
		
        TokenSamlService tokenSamlService=new TokenSamlServiceImpl();
        TokenBean tokenBean = new TokenBean();
        tokenBean=tokenSamlService.createTokenSaml("https://control.audiencie.x/ws/", "user@service.com", true);
       
     
		return tokenBean;
	}	



}

