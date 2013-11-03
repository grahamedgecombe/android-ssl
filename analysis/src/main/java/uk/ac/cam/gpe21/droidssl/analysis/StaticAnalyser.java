package uk.ac.cam.gpe21.droidssl.analysis;

import soot.*;
import soot.options.Options;
import uk.ac.cam.gpe21.droidssl.analysis.trans.*;

import java.util.Arrays;

public final class StaticAnalyser {
	public static void main(String[] args) {
		if (args.length != 1) {
			System.err.println("Usage:");
			System.err.println("  java -cp ... " + StaticAnalyser.class.getName() + " apkfile");
			System.exit(1);
		}

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
		 * Set the path to the Android SDK.
		 */
		Options.v().set_android_jars("/opt/android/platforms");

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

		/*
		 * Add transforms to the Whole Jimple Pre-processing Pack.
		 */
		Pack wjpp = PackManager.v().getPack("wjpp");
		wjpp.add(new Transform("wjpp.activity_entry_transformer", new ActivityEntryTransformer()));
		wjpp.add(new Transform("wjpp.known_vulnerable_class_tagger", new KnownVulnerableClassTagger()));

		/*
		 * Add transforms to the Jimple Transformation Pack.
		 */
		Pack jtp = PackManager.v().getPack("jtp");
		jtp.add(new Transform("jtp.jsse_hostname_verifier", new JsseHostnameVerifierTransformer()));
		jtp.add(new Transform("jtp.httpclient_hostname_verifier", new HttpClientHostnameVerifierTransformer()));
		jtp.add(new Transform("jtp.default_jsse_hostname_verifier", new DefaultJsseHostnameVerifierTransformer()));
		jtp.add(new Transform("jtp.x509_trust_manager", new X509TrustManagerTransformer()));

		/*
		 * Perform the analysis.
		 */
		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();
	}
}
