package org.owasp.webscarab.plugin.xsscrlfng;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

public class TokenGenerator {
	
	// ID used to generate parameters for tests, in order to have an unique identifier for each test
	private static AtomicInteger uniqueId  = new AtomicInteger();

	// Model used to get initialization values
	private final XSSCRLFngModel model;

	private final static Logger LOGGER = Logger.getLogger(TokenGenerator.class.getName());

	// Character used to generate long values
	private final static char CHAR_TO_REPEAT = 'A';
	
	private final static String PATTERN_PREFIX = "EDW-";
	private final static String PATTERN_SUFFIX = "_EDW";
	
	private final static String SQLI_TOKENS[][] = {{ " AND 1=2", " AND 2=3", " AND0O", " OR0O"," AND 4=3", " AND 5=5", " OR 7=7", " OR 9=9 OR 10=11"},
														{ "''", "''''", "'", "'''","' AND 'A1'='B2", "' AND 'C3'='C3", "' OR 'D4'='D4", "' OR 'F5'='F5' OR 'G6'='H7"}};
	// Perform or not SQLi tests
	private Boolean performSQLiTests = Boolean.FALSE;

	
	public TokenGenerator(final XSSCRLFngModel model, final Boolean performSQLiTests) {
		this.model = model;
		this.performSQLiTests = performSQLiTests;
	}

	/** Generates an array of crafted values to be used to test a parameter.
	* It handles inclusion of a unique ID for each call and include values for SQL Injection testing if needed.
	* Format of the arrays included is: {value generated for the test, type of the test, [optional] index of the type(for SQLi tests)}
	* Examples of value: { "PATTERN-testXSS'_PATTERN", "XSS-test"} or { "testSQLi' OR 1=1", "SQLi-Num-1", 1}
	* @param baseParameter Value of the original parameter, used mainly for the generation of SQLi values. Use "" for a blank one
	* @return Array of crafted values to be used.
	*/
	public ArrayList<Token> generateNewTestTokensTable(final String baseParameter) throws NullPointerException {
		if (null == baseParameter) {
			throw new IllegalArgumentException ("Parameter base is null!");
		}
		
		// Generate tokens for XSS
		final String xssTokens[] = model.getXSSTestStrings().split("\\r?\\n");
		LOGGER.fine("xssTokens[]: " + Arrays.toString(xssTokens));
		
		Token tokenGenerated = null;
		final ArrayList<Token> newTestTokens = new ArrayList<Token>();
		
		for (int i=0; i<xssTokens.length;i++) {
			final String tokenValue = PATTERN_PREFIX + uniqueId.addAndGet(1) + xssTokens[i] + PATTERN_SUFFIX;
			tokenGenerated = new Token("XSS-Test", tokenValue, ""); // NOPMD by Jérémy Lebourdais on 05/04/13 20:57
			newTestTokens.add(tokenGenerated);
			LOGGER.fine("Token added for XSS: " + tokenGenerated.getTokenValue());
		}
		
		// Generate LongValue tokens
		final char[] chars = new char[5000];
		Arrays.fill(chars, CHAR_TO_REPEAT);
		
		final String newLongToken = PATTERN_PREFIX + uniqueId.addAndGet(1) + new String(chars) + PATTERN_SUFFIX;
		tokenGenerated = new Token("LongValue", newLongToken, "");
		newTestTokens.add(tokenGenerated);
		LOGGER.fine("Token added for LongValue: " + tokenGenerated.getTokenValue());
		
		// If needed, generate tokens for SQLi
		if (performSQLiTests) {
			
			final String sqliTokensType[] = {"SQLi-Num-" + uniqueId.addAndGet(1), "SQLi-Text-" + uniqueId.addAndGet(1)};
			
			for (int i=0; i<sqliTokensType.length; i++) {
				for (int j=0; j<SQLI_TOKENS[0].length;j++) {
					tokenGenerated = new Token(sqliTokensType[i], baseParameter + SQLI_TOKENS[i][j], Integer.toString(j)); // NOPMD by Jérémy Lebourdais on 05/04/13 20:57
					newTestTokens.add(tokenGenerated);
					LOGGER.fine("Token added for SQLi: "+tokenGenerated.getTokenValue());
				}
			}
		}
		return newTestTokens;
	}
	
	public Boolean getPerformSQLiTests() {
		return performSQLiTests;
	}

	public void setPerformSQLiTests(final Boolean performSQLiTests) {
		this.performSQLiTests = performSQLiTests;
	}
}
