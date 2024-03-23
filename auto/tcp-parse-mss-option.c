#include <net/tcp.h>

u16 foo(const struct tcphdr *th, u16 user_mss)
{
	return tcp_parse_mss_option(th, user_mss);
}
