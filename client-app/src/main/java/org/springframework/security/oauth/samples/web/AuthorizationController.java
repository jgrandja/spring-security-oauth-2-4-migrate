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
package org.springframework.security.oauth.samples.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Joe Grandja
 */
@Controller
public class AuthorizationController {

	@Value("${messages.base-uri}")
	private String messagesBaseUri;

	@Autowired
	@Qualifier("messagingClientAuthCodeRestTemplate")
	private OAuth2RestTemplate messagingClientAuthCodeRestTemplate;

	@Autowired
	@Qualifier("messagingClientClientCredsRestTemplate")
	private OAuth2RestTemplate messagingClientClientCredsRestTemplate;

	@Autowired
	@Qualifier("messagingClientPasswordRestTemplate")
	private OAuth2RestTemplate messagingClientPasswordRestTemplate;


	@GetMapping(value = "/authorize", params = "grant_type=authorization_code")
	public String authorization_code_grant(Model model) {
		String[] messages = this.messagingClientAuthCodeRestTemplate.getForObject(this.messagesBaseUri, String[].class);
		model.addAttribute("messages", messages);
		return "index";
	}

	@GetMapping("/authorized")		// registered redirect_uri for authorization_code
	public String authorized(Model model) {
		String[] messages = this.messagingClientAuthCodeRestTemplate.getForObject(this.messagesBaseUri, String[].class);
		model.addAttribute("messages", messages);
		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials")
	public String client_credentials_grant(Model model) {
		String[] messages = this.messagingClientClientCredsRestTemplate.getForObject(this.messagesBaseUri, String[].class);
		model.addAttribute("messages", messages);
		return "index";
	}

	@PostMapping(value = "/authorize", params = "grant_type=password")
	public String password_grant(Model model, HttpServletRequest request) {
		ResourceOwnerPasswordResourceDetails passwordResourceDetails =
				(ResourceOwnerPasswordResourceDetails) this.messagingClientPasswordRestTemplate.getResource();
		passwordResourceDetails.setUsername(request.getParameter("username"));
		passwordResourceDetails.setPassword(request.getParameter("password"));

		String[] messages = this.messagingClientPasswordRestTemplate.getForObject(this.messagesBaseUri, String[].class);
		model.addAttribute("messages", messages);

		// Never store the user's credentials
		passwordResourceDetails.setUsername(null);
		passwordResourceDetails.setPassword(null);

		return "index";
	}
}