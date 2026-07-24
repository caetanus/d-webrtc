/// unit-threaded entry point. Test modules are listed explicitly so reflection
/// stays fast and the build stays deterministic.
import unit_threaded;

int main(string[] args)
{
	return args.runTests!(
		"tests.stun.message_test",
		"tests.stun.xoraddr_test",
		"tests.util.hmac_test",
		"tests.sctp.crc32c_test",
		"tests.sctp.packet_test",
	);
}
