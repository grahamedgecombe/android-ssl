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

package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.RefType;
import soot.Scene;
import soot.SootClass;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.tag.HostnameVerifierTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Set;

public final class KnownHostnameVerifierAnalyser extends Analyser {
	public KnownHostnameVerifierAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	private void tag(RefType ref, VulnerabilityState state) {
		SootClass clazz = Scene.v().getSootClass(ref.getClassName());
		clazz.addTag(new HostnameVerifierTag(state));
	}

	@Override
	public void analyse() {
		tag(Types.ALLOW_ALL_HOSTNAME_VERIFIER, VulnerabilityState.VULNERABLE);
		tag(Types.BROWSER_COMPAT_HOSTNAME_VERIFIER, VulnerabilityState.SAFE);
		tag(Types.STRICT_HOSTNAME_VERIFIER, VulnerabilityState.SAFE);
	}
}
