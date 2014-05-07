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

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class PlainServer {
	public static void main(String[] args) throws IOException {
		System.setProperty("java.net.preferIPv4Stack" ,"true");
		PlainServer server = new PlainServer();
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final ServerSocket serverSocket;

	public PlainServer() throws IOException {
		this.serverSocket = new ServerSocket(12345);
	}

	public void start() throws IOException {
		while (true) {
			Socket socket = serverSocket.accept();
			executor.execute(new EchoRunnable(socket));
		}
	}
}
