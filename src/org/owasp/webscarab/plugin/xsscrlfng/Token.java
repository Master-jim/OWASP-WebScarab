package org.owasp.webscarab.plugin.xsscrlfng;

public class Token {
	
	private String tokenType = "";
	private String tokenValue = "";
	private String tokenIndex = "";
	
	
	public Token(final String tokenType, final String tokenValue, final String tokenIndex) {
		this.tokenType = tokenType;
		this.tokenValue = tokenValue;
		this.tokenIndex = tokenIndex;
	}
	
	public String getTokenType() {
		return tokenType;
	}
	public void setTokenType(final String tokenType) {
		this.tokenType = tokenType;
	}
	public String getTokenValue() {
		return tokenValue;
	}
	public void setTokenValue(final String tokenValue) {
		this.tokenValue = tokenValue;
	}
	public String getTokenIndex() {
		return tokenIndex;
	}
	public void setTokenIndex(final String tokenIndex) {
		this.tokenIndex = tokenIndex;
	}
	
	public Boolean hasIndex()
	{
		Boolean indexFound = Boolean.FALSE;
		if (! "".equals(tokenIndex)) {
			indexFound = Boolean.TRUE;
		}
		return indexFound;
	}
	 
}
