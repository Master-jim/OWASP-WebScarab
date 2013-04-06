package org.owasp.webscarab.plugin.xsscrlfng;

/** Represents a token, which consists of:
 * a type of a test (XSS, SQLi-Num, SQLi-Text, etc),
 * a generated value,
 * an Id (int value incremented for each new Token, cf. TokenGenerator)
 * and an optional index, which is used when a test needs more than one token (typically the SQL injection tokens).
 *  
 * @author Jérémy Lebourdais
 * @see TokenGenerator
 *
 */
public class Token {
	
	// Type of the token, like XSS-Test, SQLi-Num, SQLi-Test, etc
	private String tokenType = "";
	// Value generated for this token
	private String tokenValue = "";
	// Id of this token, should be unique in one session
	private int tokenId = 0;
	// Index of this token if it is used in a subset, like for SQLi tests where 8 values are used for one test
	private int tokenTestIndex = 0;
	
	/** Creates a new instance.
	 * @param tokenType type of a test (XSS, SQLi-Num, SQLi-Text, etc),
	 * @param tokenValue generated value (the one which will be injected)
	 * @param tokenId Id of the token in the session (int value incremented for each new Token, cf. TokenGenerator)
	 * @param tokenIndex optional index (0 if not used), which is used when a test needs more than one token (typically the SQL injection tokens).
	 */
	public Token(final String tokenType, final String tokenValue, final int tokenId, final int tokenIndex) {
		this.tokenType = tokenType;
		this.tokenValue = tokenValue;
		this.tokenId = tokenId;
		this.tokenTestIndex = tokenIndex;
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
	public int getTokenId() {
		return tokenId;
	}
	public void setTokenId(final int newValue) {
		if (newValue > 0) {
			this.tokenId = newValue;
		}
	}
	
	public Boolean hasIndex()
	{
		return (tokenTestIndex > 0);
	}

	public int getTokenTestIndex() {
		return tokenTestIndex;
	}

	public void setTokenTestIndex(int newValue) {
		if (newValue > 0) {
			this.tokenTestIndex = newValue;
		}
	}
	
	public String toString() {
		return tokenType + ":" + tokenId + ":" + tokenTestIndex + ":" + tokenValue;
	}
	 
}
