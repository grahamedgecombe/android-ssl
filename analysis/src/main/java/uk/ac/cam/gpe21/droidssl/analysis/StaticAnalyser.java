package uk.ac.cam.gpe21.droidssl.analysis;

import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.util.Arrays;

public final class StaticAnalyser {
	public static void main(String[] args) {
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_output_format(Options.output_format_none);
		Options.v().set_android_jars("/opt/android/platforms");
		Options.v().set_process_dir(Arrays.asList("test-hv/build/apk/test-hv-release-unsigned.apk"));
		Options.v().set_unfriendly_mode(true);

		PackManager.v().getPack("jtp").add(new Transform("jtp.allow_all_hostname_verifier", new AllowAllHostnameVerifierTransformer()));

		soot.Main.main(new String[0]);
	}
}
