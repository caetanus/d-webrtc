import unit_threaded;
int main(string[] args)
{
	return args.runTests!(
		"tests.stun.message_test",
	);
}
