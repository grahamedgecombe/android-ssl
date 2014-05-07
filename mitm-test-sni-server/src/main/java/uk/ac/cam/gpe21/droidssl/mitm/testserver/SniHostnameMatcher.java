/*
 * Copyright 2013-2014 Graham Edgecombe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

public final class SniHostnameMatcher extends SNIMatcher {
	private String hostname;

	protected SniHostnameMatcher() {
		super(StandardConstants.SNI_HOST_NAME);
	}

	@Override
	public boolean matches(SNIServerName name) {
		SNIHostName hostname = (SNIHostName) name;
		String str = hostname.getAsciiName();
		boolean accept = str.equals("default.example.com") || str.equals("test1.example.com") || str.equals("test2.example.com");
		if (accept) {
			this.hostname = str;
		}
		return accept;
	}

	public boolean isSniEnabled() {
		return hostname != null;
	}

	public String getSniHostname() {
		return hostname;
	}
}
