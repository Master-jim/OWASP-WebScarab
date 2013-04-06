package org.owasp.webscarab.plugin.xsscrlfng;

import java.util.Iterator;

public class Tester {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		testTokenGenerator();
	}
	public static void testTokenGenerator() {
		ConfigurationHolder ch = new ConfigurationHolder();
		TokenGenerator tg = new TokenGenerator(ch);
		Iterator<Token> iterator = tg.generateNewTestTokensTable("BASE").iterator();
		while (iterator.hasNext()) {
			System.out.println(iterator.next());
		}
		ch.setPerformSQLiTests(Boolean.TRUE);
		iterator = tg.generateNewTestTokensTable("BASE_SQL").iterator();
		while (iterator.hasNext()) {
			System.out.println(iterator.next());
		}
		
	}

}
