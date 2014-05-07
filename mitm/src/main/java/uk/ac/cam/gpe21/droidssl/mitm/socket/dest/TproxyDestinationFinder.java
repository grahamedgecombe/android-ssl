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

package uk.ac.cam.gpe21.droidssl.mitm.socket.dest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class TproxyDestinationFinder extends DestinationFinder {
	@Override
	public InetSocketAddress getDestination(Socket socket) throws IOException {
		return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}
}
