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

package uk.ac.cam.gpe21.droidssl.mitm.ui.headless;

import uk.ac.cam.gpe21.droidssl.mitm.ui.Session;
import uk.ac.cam.gpe21.droidssl.mitm.ui.UserInterface;
import uk.ac.cam.gpe21.droidssl.mitm.util.HexFormat;

import java.io.IOException;

public final class HeadlessUserInterface extends UserInterface {
	@Override
	public void init(String title, String caPrefix, String hostnameFinder) {
		/* empty */
	}

	@Override
	public void onOpen(Session session) {
		/* empty */
	}

	@Override
	public void onData(Session session, boolean receive, byte[] buf, int len) {
		System.out.println(HexFormat.format(buf, len));
	}

	@Override
	public void onClose(Session session) {
		/* empty */
	}

	@Override
	public void onFailure(Session session, IOException reason) {
		/* empty */
	}
}
