package org.owasp.webscarab.plugin.xsscrlfng;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class ConfigurationHolder {
	private Boolean performSQLiTests = Boolean.FALSE;
	private String xssTestStrings = "";
	
	// Character used to generate long values
	private char tokenCharToRepeat = 'A';

	private String tokenPrefix = "EDW-";
	private String tokenSuffix = "_EDW";
	
	private TokenConfigurator sqliTextTokensConf = null;
	private TokenConfigurator sqliNumTokensConf = null;
	private List<TokenConfigurator> sqliConfigurators = null;
	
	public List<TokenConfigurator> getSqliConfigurators() {
		return sqliConfigurators;
	}

	public void setSqliConfigurators(List<TokenConfigurator> sqliConfigurators) {
		this.sqliConfigurators = sqliConfigurators;
	}

	public TokenConfigurator getSqliNumTokensConf() {
		return sqliNumTokensConf;
	}

	public void setSqliNumTokensConf(TokenConfigurator sqliNumTokensConf) {
		this.sqliNumTokensConf = sqliNumTokensConf;
	}

	public TokenConfigurator getSqliTextTokensConf() {
		return sqliTextTokensConf;
	}

	public void setSqliTextTokensConf(TokenConfigurator sqliTextTokensConf) {
		this.sqliTextTokensConf = sqliTextTokensConf;
	}

	public ConfigurationHolder() {
		// TODO: Integrate this in a more dynamic way
		HashSet<String> sqliNumTests = new HashSet<String>();
		sqliNumTests.add(" AND 1=2");
		sqliNumTests.add(" AND 2=3");
		sqliNumTests.add(" AND0O");
		sqliNumTests.add(" OR0O");
		sqliNumTests.add(" AND 4=3");
		sqliNumTests.add(" AND 5=5");
		sqliNumTests.add(" OR 7=7");
		sqliNumTests.add(" OR 9=9 OR 10=11");
		sqliNumTokensConf = new TokenConfigurator("SQLi-Num-", sqliNumTests);
		
		HashSet<String> sqliTextTests = new HashSet<String>();
		sqliTextTests.add("''");
		sqliTextTests.add("''''");
		sqliTextTests.add("'");
		sqliTextTests.add("'''");
		sqliTextTests.add("' AND 'A1'='B2");
		sqliTextTests.add("' AND 'C3'='C3");
		sqliTextTests.add("' OR 'D4'='D4");
		sqliTextTests.add("' OR 'F5'='F5' OR 'G6'='H7");
		sqliTextTokensConf = new TokenConfigurator("SQLi-Text-", sqliTextTests);

		sqliConfigurators = new ArrayList<TokenConfigurator>();
		sqliConfigurators.add(sqliNumTokensConf);
		sqliConfigurators.add(sqliTextTokensConf);
	}

	public Boolean getPerformSQLiTests() {
		return performSQLiTests;
	}

	public void setPerformSQLiTests(final Boolean performSQLiTests) {
		this.performSQLiTests = performSQLiTests;
	}

	public String getXssTestStrings() {
		return xssTestStrings;
	}

	public void setXssTestStrings(final String xssTestStrings) {
		this.xssTestStrings = xssTestStrings;
	}

	public char getTokenCharToRepeat() {
		return tokenCharToRepeat;
	}

	public void setTokenCharToRepeat(final char tokenCharToRepeat) {
		this.tokenCharToRepeat = tokenCharToRepeat;
	}

	public String getTokenPrefix() {
		return tokenPrefix;
	}

	public void setTokenPrefix(final String tokenPrefix) {
		this.tokenPrefix = tokenPrefix;
	}

	public String getTokenSuffix() {
		return tokenSuffix;
	}

	public void setTokenSuffix(final String tokenSuffix) {
		this.tokenSuffix = tokenSuffix;
	}
}
