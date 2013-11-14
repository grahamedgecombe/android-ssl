package uk.ac.cam.gpe21.droidssl.analysis;

import soot.*;
import soot.options.Options;
import uk.ac.cam.gpe21.droidssl.analysis.trans.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class StaticAnalyser {
	public static void main(String[] args) {
		if (args.length != 1) {
			System.err.println("Usage:");
			System.err.println("  java -cp ... " + StaticAnalyser.class.getName() + " apkfile");
			System.exit(1);
		}

		/*
		 * Write Soot's debug messages to stderr.
		 */
		G.v().out = System.err;

		/*
		 * Set path to input APK.
		 */
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_dir(Arrays.asList(args[0]));

		/*
		 * Prevent Soot from outputting *.jimple files.
		 */
		Options.v().set_output_format(Options.output_format_none);

		/*
		 * Set the path to the Android SDK. Whilst Soot contains code to try to
		 * detect the target SDK version, some applications use methods only
		 * present in the newer SDK, causing SPARK to crash. Therefore we force
		 * the use of the latest version of the Android SDK (4.3).
		 */
		Options.v().set_force_android_jar("/opt/android/platforms/android-18/android.jar");

		/*
		 * Allow phantom references as there are some Google-specific APIs not
		 * included in the Android SDK directory as listed above.
		 */
		Options.v().set_allow_phantom_refs(true);

		/*
		 * Enable the SPARK points-to analysis.
		 */
		Options.v().set_whole_program(true);
		PhaseOptions.v().processPhaseOptions("cg.spark", "enabled:true");

		List<Vulnerability> vulnerabilities = new ArrayList<>();

		/*
		 * Add transforms to the Whole Jimple Pre-processing Pack.
		 */
		Pack wjpp = PackManager.v().getPack("wjpp");
		wjpp.add(new Transform("wjpp.activity_entry_transformer", new EntryMethodTransformer()));

		/*
		 * Add transforms to the Whole Jimple Transformation Pack.
		 */
		AnalysisTransformer transformer = new AnalysisTransformer(
			/* find vulnerable HostnameVerifiers */
			new KnownHostnameVerifierAnalyser(vulnerabilities),
			new HostnameVerifierAnalyser(vulnerabilities),
			new AbstractVerifierAnalyser(vulnerabilities),

			/* find places where HostnameVerifiers are used */
			new DefaultHostnameVerifierAnalyser(vulnerabilities),
			new HttpsUrlConnectionAnalyser(vulnerabilities),

			/* find vulnerable X509TrustManagers */
			new TrustManagerAnalyser(vulnerabilities),

			/* find places where X509TrustManagers are used */
			new SslContextAnalyser(vulnerabilities)
		);

		Pack wjtp = PackManager.v().getPack("wjtp");
		wjtp.add(new Transform("wjtp.analysis", transformer));

		/*
		 * Perform the analysis.
		 */
		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();

		/*
		 * Print out the list of vulnerabilities.
		 */
		for (Vulnerability vulnerability : vulnerabilities) {
			System.out.println(vulnerability.toString());
		}
	}
}
