/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.samples.config;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Joe Grandja
 */
class KeyConfig {
	private static final String KEY_STORE_FILE = ".keystore-oauth2-demo";
	private static final String KEY_STORE_PASSWORD = "admin1234";
	private static final String KEY_ALIAS = "oauth2-demo-key";
	private static KeyStoreKeyFactory KEY_STORE_KEY_FACTORY = new KeyStoreKeyFactory(
			new ClassPathResource(KEY_STORE_FILE), KEY_STORE_PASSWORD.toCharArray());
	static final String VERIFIER_KEY_ID = new String(Base64.encode(KeyGenerators.secureRandom(32).generateKey()));

	static RSAPublicKey getVerifierKey() {
		return (RSAPublicKey) getKeyPair().getPublic();
	}

	static RSAPrivateKey getSignerKey() {
		return (RSAPrivateKey) getKeyPair().getPrivate();
	}

	private static KeyPair getKeyPair() {
		return KEY_STORE_KEY_FACTORY.getKeyPair(KEY_ALIAS);
	}
}