package xyz.b8mg.services;

import org.opensaml.common.SAMLException;

import xyz.b8mg.bean.TokenBean;

public interface TokenSamlService {

	public TokenBean createTokenSaml(String input_audiencie, String input_issuer, boolean fail) throws Exception;
	public void validateTokenSaml(String xml, String urlSp) throws SAMLException;
	
}
