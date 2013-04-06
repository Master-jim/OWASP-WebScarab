package org.owasp.webscarab.plugin.xsscrlfng;

import java.util.HashSet;
import java.util.Set;

public class TokenConfigurator {
	
	
	private String tokenTestName = null;
	private Set<String> tokenValues = new HashSet<String>();
	
	/** Creates a configuration to generate tokens.
	 * @param tokenTestName Name of the test for the purpose of the token (SQLi-Num, SQLi-Text, XSS, LongValue, etc.
	 * @param tokenValues Ordered values to use for generation of the token.
	 */
	public TokenConfigurator(final String tokenTestName, final Set<String> tokenValues) {
		this.tokenTestName = tokenTestName;
		this.tokenValues = tokenValues;
	}
	
	public String getTokenTestName() {
		return tokenTestName;
	}
	
	public void setTokenTestName(final String tokenTestName) {
		this.tokenTestName = tokenTestName;
	}
	
	public Set<String> getTokenValues() {
		return tokenValues;
	}
	
	public void setTokenValues(final Set<String> tokenValues) {
		this.tokenValues = tokenValues;
	}
	

}
