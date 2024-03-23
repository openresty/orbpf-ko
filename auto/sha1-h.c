#include <crypto/sha1.h>

void foo(u8 *data) {
	u32 digest[SHA1_DIGEST_WORDS];
	u32 ws[SHA1_WORKSPACE_WORDS];

	sha1_init(digest);
	sha1_transform(digest, data, ws);
}
