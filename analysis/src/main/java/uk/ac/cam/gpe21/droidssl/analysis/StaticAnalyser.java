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

package uk.ac.cam.gpe21.droidssl.analysis;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import soot.*;
import soot.options.Options;
import uk.ac.cam.gpe21.droidssl.analysis.trans.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class StaticAnalyser {
	@SuppressWarnings("unchecked")
	public static void main(String[] args) {
		OptionParser parser = new OptionParser();
		parser.accepts("paddle");

		OptionSet set = parser.parse(args);
		List<?> apk = set.nonOptionArguments();
		if (apk.size() != 1) {
			System.out.println("Usage:");
			System.out.println("  java -cp ... " + StaticAnalyser.class.getName() + " [--paddle] apkfile");
			System.exit(1);
		}

		try {
			/*
			 * Write Soot's debug messages to stdout.
			 * (stderr would be more appropriate, but Soot has some code which uses
			 * System.out.println() directly. Therefore we use stderr for the
			 * actual output of interest, and stdout for everything else.)
			 */
			G.v().out = System.out;

			/*
			 * Set path to input APK.
			 */
			Options.v().set_src_prec(Options.src_prec_apk);
			Options.v().set_process_dir((List<String>) apk);

			/*
			 * Prevent Soot from outputting *.jimple files.
			 */
			Options.v().set_output_format(Options.output_format_jimple);

			/*
			 * Set the path to the Android SDK. Whilst Soot contains code to try to
			 * detect the target SDK version, some applications use methods only
			 * present in the newer SDK, causing SPARK to crash. Therefore we force
			 * the use of the latest version of the Android SDK (4.4).
			 */
			Options.v().set_force_android_jar("/opt/android/platforms/android-19/android.jar");

			/*
			 * Allow phantom references as there are some Google-specific APIs not
			 * included in the Android SDK directory as listed above.
			 */
			Options.v().set_allow_phantom_refs(true);

			/*
			 * Enable the SPARK or Paddle points-to analysis.
			 */
			Options.v().set_whole_program(true);
			if (set.has("paddle")) {
				PhaseOptions.v().processPhaseOptions("cg.paddle", "enabled:true");
			} else {
				PhaseOptions.v().processPhaseOptions("cg.spark", "enabled:true");
			}

			Set<Vulnerability> vulnerabilities = new HashSet<>();

			/*
			 * Add transforms to the Whole Jimple Pre-processing Pack.
			 */
			Pack wjpp = PackManager.v().getPack("wjpp");
			wjpp.add(new Transform("wjpp.activity_entry_transformer", new EntryMethodTransformer()));

			/*
			 * Add transforms to the Whole Jimple Transformation Pack.
			 */
			AnalysisTransformer transformer = new AnalysisTransformer(
				vulnerabilities,

				/* find vulnerable HostnameVerifiers */
				new KnownHostnameVerifierAnalyser(vulnerabilities),
				new HostnameVerifierAnalyser(vulnerabilities),
				new AbstractVerifierAnalyser(vulnerabilities),

				/* find places where HostnameVerifiers are used */
				new InitHostnameVerifierAnalyser(vulnerabilities),
				new DefaultHostnameVerifierAnalyser(vulnerabilities),
				new HttpsUrlConnectionAnalyser(vulnerabilities),

				/* find vulnerable X509TrustManagers */
				new TrustManagerAnalyser(vulnerabilities),

				/* find places where X509TrustManagers are used */
				new InitTrustManagerAnalyser(vulnerabilities),
				new SslContextAnalyser(vulnerabilities)
			);

			Pack wjtp = PackManager.v().getPack("wjtp");
			wjtp.add(new Transform("wjtp.analysis", transformer));

			/*
			 * Perform the analysis.
			 */
			Scene.v().loadNecessaryClasses();
			Options.v().set_unfriendly_mode(true);
			Main.main(new String[0]);

			/*
			 * Print out the list of vulnerabilities.
			 */
			System.out.println(vulnerabilities.size() + " vulnerabilities:");
			System.out.flush();
			for (Vulnerability vulnerability : vulnerabilities) {
				System.err.println(vulnerability.toString());
			}
		} catch (Throwable t) {
			/* use stdout for the same reason as above */
			t.printStackTrace(System.out);

			/*
			 * Print out FAILED so we can tell the difference between a failure
			 * or just a lack of vulnerabilities.
			 */
			System.err.println("\t\tFAILED");
		}
	}
}
