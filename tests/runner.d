import unit_threaded;
int main(string[] args)
{
	return args.runTests!(
		"tests.stun.message_test",
		"tests.ice.agent_test",
		"tests.dtls.certificate_test",
		"tests.dtls.transport_test",
		"tests.sctp.packet_test",
		"tests.sctp.association_test",
		"tests.sctp.transfer_test",
	);
}
