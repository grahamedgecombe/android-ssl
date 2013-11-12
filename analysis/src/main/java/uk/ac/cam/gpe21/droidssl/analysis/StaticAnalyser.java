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

		List<Vulnerability> vulnerabilities = new ArrayList<>();

		/*
		 * Add transforms to the Whole Jimple Pre-processing Pack.
		 */
		Pack wjpp = PackManager.v().getPack("wjpp");
		wjpp.add(new Transform("wjpp.activity_entry_transformer",    new ActivityEntryTransformer()));
		wjpp.add(new Transform("wjpp.known_vulnerable_class_tagger", new KnownVulnerableClassTagger()));

		/*
		 * Add transforms to the Jimple Transformation Pack.
		 */
		Pack jtp = PackManager.v().getPack("jtp");
		jtp.add(new Transform("jtp.hostname_verifier",         new HostnameVerifierAnalyser(vulnerabilities)));
		jtp.add(new Transform("jtp.abstract_verifier",         new AbstractVerifierAnalyser(vulnerabilities)));
		jtp.add(new Transform("jtp.default_hostname_verifier", new DefaultHostnameVerifierAnalyser(vulnerabilities)));
		jtp.add(new Transform("jtp.trust_manager",             new TrustManagerAnalyser(vulnerabilities)));
		jtp.add(new Transform("jtp.ssl_context",               new SslContextAnalyser(vulnerabilities)));

		/*
		 * Perform the analysis.
		 */
		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();

		/*
		 * TODO: temporary fix - the JTP transforms are executed for each
		 * method, and then for each transform, however, we really need this to
		 * be the other way around so that classes identified as being bad in
		 * earlier transforms (e.g. hostname_verifier) can be made use of in
		 * later transforms (e.g. ssl_context).
		 */
		PackManager.v().runPacks();

		/*
		 * Print out the list of vulnerabilities.
		 */
		System.err.println(vulnerabilities.size() + " vulnerabilities found:");
		for (Vulnerability vulnerability : vulnerabilities) {
			System.err.println("  " + vulnerability.toString());
		}
	}
}
