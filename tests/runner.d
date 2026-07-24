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
		"tests.sctp.chunk_test",
		"tests.sctp.sack_test",
		"tests.sctp.reassembly_test",
		"tests.sctp.payload_test",
		"tests.sctp.pending_test",
		"tests.sctp.timer_test",
		"tests.datachannel.message_test",
		"tests.sctp.association_test",
	);
}
