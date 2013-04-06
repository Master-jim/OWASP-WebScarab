package org.owasp.webscarab.plugin.xsscrlfng;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

public class TokenGenerator {
	
	// ID used to generate parameters for tests, in order to have an unique identifier for each test
	private static AtomicInteger uniqueId  = new AtomicInteger();

	// TODO Create a dedicated Configuration class to hold configuration values.
	// Model used to get initialization values
	private final ConfigurationHolder configuration;

	private final static Logger LOGGER = Logger.getLogger(TokenGenerator.class.getName());

	
	public TokenGenerator(final ConfigurationHolder configuration) {
		this.configuration = configuration;
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
		final String xssTokens[] = configuration.getXssTestStrings().split("\\r?\\n");
		LOGGER.fine("xssTokens[]: " + Arrays.toString(xssTokens));
		
		Token tokenGenerated = null;
		final ArrayList<Token> newTestTokens = new ArrayList<Token>();
		int tokenId = 0;
		
		// TODO: transform this with the TokenConfigurator
		for (int i=0; i<xssTokens.length;i++) {
			tokenId = uniqueId.addAndGet(1);
			final String tokenValue = configuration.getTokenPrefix() + tokenId + xssTokens[i] + configuration.getTokenSuffix();
			tokenGenerated = new Token("XSS-Test", tokenValue, tokenId, 0); // NOPMD by Jérémy Lebourdais on 05/04/13 20:57
			newTestTokens.add(tokenGenerated);
			LOGGER.fine("Token added for XSS: " + tokenGenerated.getTokenValue());
		}
		
		// Generate LongValue tokens
		final char[] chars = new char[5000];
		Arrays.fill(chars, configuration.getTokenCharToRepeat());
		tokenId = uniqueId.addAndGet(1);
		final String newLongTokenValue = configuration.getTokenPrefix() + tokenId + new String(chars) + configuration.getTokenSuffix();
		tokenGenerated = new Token("LongValue", newLongTokenValue, tokenId, 0);
		newTestTokens.add(tokenGenerated);
		LOGGER.fine("Token added for LongValue: " + tokenGenerated.getTokenValue());
		
		// If needed, generate tokens for SQLi
		if (configuration.getPerformSQLiTests()) {
			final Iterator<TokenConfigurator> confIterator = configuration.getSqliConfigurators().iterator();
			
			while (confIterator.hasNext()) {
				// Id of the generated SQL Test
				tokenId = uniqueId.addAndGet(1);
				// Get the TokenConfigurator
				final TokenConfigurator currentTokenConfigurator = confIterator.next();
				
				// Retrieve associated values and create tokens
				final Iterator<String> sqliValueIterator = currentTokenConfigurator.getTokenValues().iterator();
				int index = 0;
				while (sqliValueIterator.hasNext()) {
					index++;
					
					tokenGenerated = new Token(currentTokenConfigurator.getTokenTestName(), baseParameter + sqliValueIterator.next(), tokenId, index); // NOPMD by Jérémy Lebourdais on 05/04/13 20:57
					newTestTokens.add(tokenGenerated);
					LOGGER.fine("Token added for SQLi: "+tokenGenerated.getTokenValue());
				}
			}
		}
		return newTestTokens;
	}
	
}
