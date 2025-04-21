/*  whrlpool.cpp - originally modified by Kevin Springle from
 *  Paulo Barreto and Vincent Rijmen's public domain code, whirlpool.c.
 *  Updated to Whirlpool version 3.0, optimized and SSE version added by Wei Dai
 *  All modifications are placed in the public domain
 */

 /*
  * Adapted to VeraCrypt
  */

/* This is the original introductory comment: */

/**
 * The Whirlpool hashing function.
 *
 * <P>
 * <b>References</b>
 *
 * <P>
 * The Whirlpool algorithm was developed by
 * <a href="mailto:pbarreto@scopus.com.br">Paulo S. L. M. Barreto</a> and
 * <a href="mailto:vincent.rijmen@cryptomathic.com">Vincent Rijmen</a>.
 *
 * See
 *      P.S.L.M. Barreto, V. Rijmen,
 *      ``The Whirlpool hashing function,''
 *      NESSIE submission, 2000 (tweaked version, 2001),
 *      <https://www.cosic.esat.kuleuven.ac.be/nessie/workshop/submissions/whirlpool.zip>
 * 
 * @author  Paulo S.L.M. Barreto
 * @author  Vincent Rijmen.
 *
 * @version 3.0 (2003.03.12)
 *
 * =============================================================================
 *
 * Differences from version 2.1:
 *
 * - Suboptimal diffusion matrix replaced by cir(1, 1, 4, 1, 8, 5, 2, 9).
 *
 * =============================================================================
 *
 * Differences from version 2.0:
 *
 * - Generation of ISO/IEC 10118-3 test vectors.
 * - Bug fix: nonzero carry was ignored when tallying the data length
 *      (this bug apparently only manifested itself when feeding data
 *      in pieces rather than in a single chunk at once).
 * - Support for MS Visual C++ 64-bit integer arithmetic.
 *
 * Differences from version 1.0:
 *
 * - Original S-box replaced by the tweaked, hardware-efficient version.
 *
 * =============================================================================
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Common/Tcdefs.h"
#include "Common/Endian.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif

#include "cpu.h"

#include "misc.h"
#include "Whirlpool.h"

// "Inline assembly operands don't work with .intel_syntax",
//   http://llvm.org/bugs/show_bug.cgi?id=24232
#if defined(CRYPTOPP_DISABLE_INTEL_ASM)
# undef CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
# undef CRYPTOPP_BOOL_SSSE3_ASM_AVAILABLE
# define CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE 0
# define CRYPTOPP_BOOL_SSSE3_ASM_AVAILABLE 0
#endif

/*
 * The number of rounds of the internal dedicated block cipher.
 */
#define R 10

/*
 * Though Whirlpool is endianness-neutral, the encryption tables are listed
 * in BIG-ENDIAN format, which is adopted throughout this implementation
 * (but little-endian notation would be equally suitable if consistently
 * employed).
 */

#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
CRYPTOPP_ALIGN_DATA(16) static const uint64 Whirlpool_C[8*256+R] CRYPTOPP_SECTION_ALIGN16 = {
#else
static const uint64 Whirlpool_C[8*256+R] = {
#endif
    LL(0x18186018c07830d8), LL(0x23238c2305af4626), LL(0xc6c63fc67ef991b8), LL(0xe8e887e8136fcdfb),
    LL(0x878726874ca113cb), LL(0xb8b8dab8a9626d11), LL(0x0101040108050209), LL(0x4f4f214f426e9e0d),
    LL(0x3636d836adee6c9b), LL(0xa6a6a2a6590451ff), LL(0xd2d26fd2debdb90c), LL(0xf5f5f3f5fb06f70e),
    LL(0x7979f979ef80f296), LL(0x6f6fa16f5fcede30), LL(0x91917e91fcef3f6d), LL(0x52525552aa07a4f8),
    LL(0x60609d6027fdc047), LL(0xbcbccabc89766535), LL(0x9b9b569baccd2b37), LL(0x8e8e028e048c018a),
    LL(0xa3a3b6a371155bd2), LL(0x0c0c300c603c186c), LL(0x7b7bf17bff8af684), LL(0x3535d435b5e16a80),
    LL(0x1d1d741de8693af5), LL(0xe0e0a7e05347ddb3), LL(0xd7d77bd7f6acb321), LL(0xc2c22fc25eed999c),
    LL(0x2e2eb82e6d965c43), LL(0x4b4b314b627a9629), LL(0xfefedffea321e15d), LL(0x575741578216aed5),
    LL(0x15155415a8412abd), LL(0x7777c1779fb6eee8), LL(0x3737dc37a5eb6e92), LL(0xe5e5b3e57b56d79e),
    LL(0x9f9f469f8cd92313), LL(0xf0f0e7f0d317fd23), LL(0x4a4a354a6a7f9420), LL(0xdada4fda9e95a944),
    LL(0x58587d58fa25b0a2), LL(0xc9c903c906ca8fcf), LL(0x2929a429558d527c), LL(0x0a0a280a5022145a),
    LL(0xb1b1feb1e14f7f50), LL(0xa0a0baa0691a5dc9), LL(0x6b6bb16b7fdad614), LL(0x85852e855cab17d9),
    LL(0xbdbdcebd8173673c), LL(0x5d5d695dd234ba8f), LL(0x1010401080502090), LL(0xf4f4f7f4f303f507),
    LL(0xcbcb0bcb16c08bdd), LL(0x3e3ef83eedc67cd3), LL(0x0505140528110a2d), LL(0x676781671fe6ce78),
    LL(0xe4e4b7e47353d597), LL(0x27279c2725bb4e02), LL(0x4141194132588273), LL(0x8b8b168b2c9d0ba7),
    LL(0xa7a7a6a7510153f6), LL(0x7d7de97dcf94fab2), LL(0x95956e95dcfb3749), LL(0xd8d847d88e9fad56),
    LL(0xfbfbcbfb8b30eb70), LL(0xeeee9fee2371c1cd), LL(0x7c7ced7cc791f8bb), LL(0x6666856617e3cc71),
    LL(0xdddd53dda68ea77b), LL(0x17175c17b84b2eaf), LL(0x4747014702468e45), LL(0x9e9e429e84dc211a),
    LL(0xcaca0fca1ec589d4), LL(0x2d2db42d75995a58), LL(0xbfbfc6bf9179632e), LL(0x07071c07381b0e3f),
    LL(0xadad8ead012347ac), LL(0x5a5a755aea2fb4b0), LL(0x838336836cb51bef), LL(0x3333cc3385ff66b6),
    LL(0x636391633ff2c65c), LL(0x02020802100a0412), LL(0xaaaa92aa39384993), LL(0x7171d971afa8e2de),
    LL(0xc8c807c80ecf8dc6), LL(0x19196419c87d32d1), LL(0x494939497270923b), LL(0xd9d943d9869aaf5f),
    LL(0xf2f2eff2c31df931), LL(0xe3e3abe34b48dba8), LL(0x5b5b715be22ab6b9), LL(0x88881a8834920dbc),
    LL(0x9a9a529aa4c8293e), LL(0x262698262dbe4c0b), LL(0x3232c8328dfa64bf), LL(0xb0b0fab0e94a7d59),
    LL(0xe9e983e91b6acff2), LL(0x0f0f3c0f78331e77), LL(0xd5d573d5e6a6b733), LL(0x80803a8074ba1df4),
    LL(0xbebec2be997c6127), LL(0xcdcd13cd26de87eb), LL(0x3434d034bde46889), LL(0x48483d487a759032),
    LL(0xffffdbffab24e354), LL(0x7a7af57af78ff48d), LL(0x90907a90f4ea3d64), LL(0x5f5f615fc23ebe9d),
    LL(0x202080201da0403d), LL(0x6868bd6867d5d00f), LL(0x1a1a681ad07234ca), LL(0xaeae82ae192c41b7),
    LL(0xb4b4eab4c95e757d), LL(0x54544d549a19a8ce), LL(0x93937693ece53b7f), LL(0x222288220daa442f),
    LL(0x64648d6407e9c863), LL(0xf1f1e3f1db12ff2a), LL(0x7373d173bfa2e6cc), LL(0x12124812905a2482),
    LL(0x40401d403a5d807a), LL(0x0808200840281048), LL(0xc3c32bc356e89b95), LL(0xecec97ec337bc5df),
    LL(0xdbdb4bdb9690ab4d), LL(0xa1a1bea1611f5fc0), LL(0x8d8d0e8d1c830791), LL(0x3d3df43df5c97ac8),
    LL(0x97976697ccf1335b), LL(0x0000000000000000), LL(0xcfcf1bcf36d483f9), LL(0x2b2bac2b4587566e),
    LL(0x7676c57697b3ece1), LL(0x8282328264b019e6), LL(0xd6d67fd6fea9b128), LL(0x1b1b6c1bd87736c3),
    LL(0xb5b5eeb5c15b7774), LL(0xafaf86af112943be), LL(0x6a6ab56a77dfd41d), LL(0x50505d50ba0da0ea),
    LL(0x45450945124c8a57), LL(0xf3f3ebf3cb18fb38), LL(0x3030c0309df060ad), LL(0xefef9bef2b74c3c4),
    LL(0x3f3ffc3fe5c37eda), LL(0x55554955921caac7), LL(0xa2a2b2a2791059db), LL(0xeaea8fea0365c9e9),
    LL(0x656589650fecca6a), LL(0xbabad2bab9686903), LL(0x2f2fbc2f65935e4a), LL(0xc0c027c04ee79d8e),
    LL(0xdede5fdebe81a160), LL(0x1c1c701ce06c38fc), LL(0xfdfdd3fdbb2ee746), LL(0x4d4d294d52649a1f),
    LL(0x92927292e4e03976), LL(0x7575c9758fbceafa), LL(0x06061806301e0c36), LL(0x8a8a128a249809ae),
    LL(0xb2b2f2b2f940794b), LL(0xe6e6bfe66359d185), LL(0x0e0e380e70361c7e), LL(0x1f1f7c1ff8633ee7),
    LL(0x6262956237f7c455), LL(0xd4d477d4eea3b53a), LL(0xa8a89aa829324d81), LL(0x96966296c4f43152),
    LL(0xf9f9c3f99b3aef62), LL(0xc5c533c566f697a3), LL(0x2525942535b14a10), LL(0x59597959f220b2ab),
    LL(0x84842a8454ae15d0), LL(0x7272d572b7a7e4c5), LL(0x3939e439d5dd72ec), LL(0x4c4c2d4c5a619816),
    LL(0x5e5e655eca3bbc94), LL(0x7878fd78e785f09f), LL(0x3838e038ddd870e5), LL(0x8c8c0a8c14860598),
    LL(0xd1d163d1c6b2bf17), LL(0xa5a5aea5410b57e4), LL(0xe2e2afe2434dd9a1), LL(0x616199612ff8c24e),
    LL(0xb3b3f6b3f1457b42), LL(0x2121842115a54234), LL(0x9c9c4a9c94d62508), LL(0x1e1e781ef0663cee),
    LL(0x4343114322528661), LL(0xc7c73bc776fc93b1), LL(0xfcfcd7fcb32be54f), LL(0x0404100420140824),
    LL(0x51515951b208a2e3), LL(0x99995e99bcc72f25), LL(0x6d6da96d4fc4da22), LL(0x0d0d340d68391a65),
    LL(0xfafacffa8335e979), LL(0xdfdf5bdfb684a369), LL(0x7e7ee57ed79bfca9), LL(0x242490243db44819),
    LL(0x3b3bec3bc5d776fe), LL(0xabab96ab313d4b9a), LL(0xcece1fce3ed181f0), LL(0x1111441188552299),
    LL(0x8f8f068f0c890383), LL(0x4e4e254e4a6b9c04), LL(0xb7b7e6b7d1517366), LL(0xebeb8beb0b60cbe0),
    LL(0x3c3cf03cfdcc78c1), LL(0x81813e817cbf1ffd), LL(0x94946a94d4fe3540), LL(0xf7f7fbf7eb0cf31c),
    LL(0xb9b9deb9a1676f18), LL(0x13134c13985f268b), LL(0x2c2cb02c7d9c5851), LL(0xd3d36bd3d6b8bb05),
    LL(0xe7e7bbe76b5cd38c), LL(0x6e6ea56e57cbdc39), LL(0xc4c437c46ef395aa), LL(0x03030c03180f061b),
    LL(0x565645568a13acdc), LL(0x44440d441a49885e), LL(0x7f7fe17fdf9efea0), LL(0xa9a99ea921374f88),
    LL(0x2a2aa82a4d825467), LL(0xbbbbd6bbb16d6b0a), LL(0xc1c123c146e29f87), LL(0x53535153a202a6f1),
    LL(0xdcdc57dcae8ba572), LL(0x0b0b2c0b58271653), LL(0x9d9d4e9d9cd32701), LL(0x6c6cad6c47c1d82b),
    LL(0x3131c43195f562a4), LL(0x7474cd7487b9e8f3), LL(0xf6f6fff6e309f115), LL(0x464605460a438c4c),
    LL(0xacac8aac092645a5), LL(0x89891e893c970fb5), LL(0x14145014a04428b4), LL(0xe1e1a3e15b42dfba),
    LL(0x16165816b04e2ca6), LL(0x3a3ae83acdd274f7), LL(0x6969b9696fd0d206), LL(0x09092409482d1241),
    LL(0x7070dd70a7ade0d7), LL(0xb6b6e2b6d954716f), LL(0xd0d067d0ceb7bd1e), LL(0xeded93ed3b7ec7d6),
    LL(0xcccc17cc2edb85e2), LL(0x424215422a578468), LL(0x98985a98b4c22d2c), LL(0xa4a4aaa4490e55ed),
	LL(0x2828a0285d885075), LL(0x5c5c6d5cda31b886), LL(0xf8f8c7f8933fed6b), LL(0x8686228644a411c2),

	LL(0xd818186018c07830), LL(0x2623238c2305af46), LL(0xb8c6c63fc67ef991), LL(0xfbe8e887e8136fcd),
    LL(0xcb878726874ca113), LL(0x11b8b8dab8a9626d), LL(0x0901010401080502), LL(0x0d4f4f214f426e9e),
    LL(0x9b3636d836adee6c), LL(0xffa6a6a2a6590451), LL(0x0cd2d26fd2debdb9), LL(0x0ef5f5f3f5fb06f7),
    LL(0x967979f979ef80f2), LL(0x306f6fa16f5fcede), LL(0x6d91917e91fcef3f), LL(0xf852525552aa07a4),
    LL(0x4760609d6027fdc0), LL(0x35bcbccabc897665), LL(0x379b9b569baccd2b), LL(0x8a8e8e028e048c01),
    LL(0xd2a3a3b6a371155b), LL(0x6c0c0c300c603c18), LL(0x847b7bf17bff8af6), LL(0x803535d435b5e16a),
    LL(0xf51d1d741de8693a), LL(0xb3e0e0a7e05347dd), LL(0x21d7d77bd7f6acb3), LL(0x9cc2c22fc25eed99),
    LL(0x432e2eb82e6d965c), LL(0x294b4b314b627a96), LL(0x5dfefedffea321e1), LL(0xd5575741578216ae),
    LL(0xbd15155415a8412a), LL(0xe87777c1779fb6ee), LL(0x923737dc37a5eb6e), LL(0x9ee5e5b3e57b56d7),
    LL(0x139f9f469f8cd923), LL(0x23f0f0e7f0d317fd), LL(0x204a4a354a6a7f94), LL(0x44dada4fda9e95a9),
    LL(0xa258587d58fa25b0), LL(0xcfc9c903c906ca8f), LL(0x7c2929a429558d52), LL(0x5a0a0a280a502214),
    LL(0x50b1b1feb1e14f7f), LL(0xc9a0a0baa0691a5d), LL(0x146b6bb16b7fdad6), LL(0xd985852e855cab17),
    LL(0x3cbdbdcebd817367), LL(0x8f5d5d695dd234ba), LL(0x9010104010805020), LL(0x07f4f4f7f4f303f5),
    LL(0xddcbcb0bcb16c08b), LL(0xd33e3ef83eedc67c), LL(0x2d0505140528110a), LL(0x78676781671fe6ce),
    LL(0x97e4e4b7e47353d5), LL(0x0227279c2725bb4e), LL(0x7341411941325882), LL(0xa78b8b168b2c9d0b),
    LL(0xf6a7a7a6a7510153), LL(0xb27d7de97dcf94fa), LL(0x4995956e95dcfb37), LL(0x56d8d847d88e9fad),
    LL(0x70fbfbcbfb8b30eb), LL(0xcdeeee9fee2371c1), LL(0xbb7c7ced7cc791f8), LL(0x716666856617e3cc),
    LL(0x7bdddd53dda68ea7), LL(0xaf17175c17b84b2e), LL(0x454747014702468e), LL(0x1a9e9e429e84dc21),
    LL(0xd4caca0fca1ec589), LL(0x582d2db42d75995a), LL(0x2ebfbfc6bf917963), LL(0x3f07071c07381b0e),
    LL(0xacadad8ead012347), LL(0xb05a5a755aea2fb4), LL(0xef838336836cb51b), LL(0xb63333cc3385ff66),
    LL(0x5c636391633ff2c6), LL(0x1202020802100a04), LL(0x93aaaa92aa393849), LL(0xde7171d971afa8e2),
    LL(0xc6c8c807c80ecf8d), LL(0xd119196419c87d32), LL(0x3b49493949727092), LL(0x5fd9d943d9869aaf),
    LL(0x31f2f2eff2c31df9), LL(0xa8e3e3abe34b48db), LL(0xb95b5b715be22ab6), LL(0xbc88881a8834920d),
    LL(0x3e9a9a529aa4c829), LL(0x0b262698262dbe4c), LL(0xbf3232c8328dfa64), LL(0x59b0b0fab0e94a7d),
    LL(0xf2e9e983e91b6acf), LL(0x770f0f3c0f78331e), LL(0x33d5d573d5e6a6b7), LL(0xf480803a8074ba1d),
    LL(0x27bebec2be997c61), LL(0xebcdcd13cd26de87), LL(0x893434d034bde468), LL(0x3248483d487a7590),
    LL(0x54ffffdbffab24e3), LL(0x8d7a7af57af78ff4), LL(0x6490907a90f4ea3d), LL(0x9d5f5f615fc23ebe),
    LL(0x3d202080201da040), LL(0x0f6868bd6867d5d0), LL(0xca1a1a681ad07234), LL(0xb7aeae82ae192c41),
    LL(0x7db4b4eab4c95e75), LL(0xce54544d549a19a8), LL(0x7f93937693ece53b), LL(0x2f222288220daa44),
    LL(0x6364648d6407e9c8), LL(0x2af1f1e3f1db12ff), LL(0xcc7373d173bfa2e6), LL(0x8212124812905a24),
    LL(0x7a40401d403a5d80), LL(0x4808082008402810), LL(0x95c3c32bc356e89b), LL(0xdfecec97ec337bc5),
    LL(0x4ddbdb4bdb9690ab), LL(0xc0a1a1bea1611f5f), LL(0x918d8d0e8d1c8307), LL(0xc83d3df43df5c97a),
    LL(0x5b97976697ccf133), LL(0x0000000000000000), LL(0xf9cfcf1bcf36d483), LL(0x6e2b2bac2b458756),
    LL(0xe17676c57697b3ec), LL(0xe68282328264b019), LL(0x28d6d67fd6fea9b1), LL(0xc31b1b6c1bd87736),
    LL(0x74b5b5eeb5c15b77), LL(0xbeafaf86af112943), LL(0x1d6a6ab56a77dfd4), LL(0xea50505d50ba0da0),
    LL(0x5745450945124c8a), LL(0x38f3f3ebf3cb18fb), LL(0xad3030c0309df060), LL(0xc4efef9bef2b74c3),
    LL(0xda3f3ffc3fe5c37e), LL(0xc755554955921caa), LL(0xdba2a2b2a2791059), LL(0xe9eaea8fea0365c9),
    LL(0x6a656589650fecca), LL(0x03babad2bab96869), LL(0x4a2f2fbc2f65935e), LL(0x8ec0c027c04ee79d),
    LL(0x60dede5fdebe81a1), LL(0xfc1c1c701ce06c38), LL(0x46fdfdd3fdbb2ee7), LL(0x1f4d4d294d52649a),
    LL(0x7692927292e4e039), LL(0xfa7575c9758fbcea), LL(0x3606061806301e0c), LL(0xae8a8a128a249809),
    LL(0x4bb2b2f2b2f94079), LL(0x85e6e6bfe66359d1), LL(0x7e0e0e380e70361c), LL(0xe71f1f7c1ff8633e),
    LL(0x556262956237f7c4), LL(0x3ad4d477d4eea3b5), LL(0x81a8a89aa829324d), LL(0x5296966296c4f431),
    LL(0x62f9f9c3f99b3aef), LL(0xa3c5c533c566f697), LL(0x102525942535b14a), LL(0xab59597959f220b2),
    LL(0xd084842a8454ae15), LL(0xc57272d572b7a7e4), LL(0xec3939e439d5dd72), LL(0x164c4c2d4c5a6198),
    LL(0x945e5e655eca3bbc), LL(0x9f7878fd78e785f0), LL(0xe53838e038ddd870), LL(0x988c8c0a8c148605),
    LL(0x17d1d163d1c6b2bf), LL(0xe4a5a5aea5410b57), LL(0xa1e2e2afe2434dd9), LL(0x4e616199612ff8c2),
    LL(0x42b3b3f6b3f1457b), LL(0x342121842115a542), LL(0x089c9c4a9c94d625), LL(0xee1e1e781ef0663c),
    LL(0x6143431143225286), LL(0xb1c7c73bc776fc93), LL(0x4ffcfcd7fcb32be5), LL(0x2404041004201408),
    LL(0xe351515951b208a2), LL(0x2599995e99bcc72f), LL(0x226d6da96d4fc4da), LL(0x650d0d340d68391a),
    LL(0x79fafacffa8335e9), LL(0x69dfdf5bdfb684a3), LL(0xa97e7ee57ed79bfc), LL(0x19242490243db448),
    LL(0xfe3b3bec3bc5d776), LL(0x9aabab96ab313d4b), LL(0xf0cece1fce3ed181), LL(0x9911114411885522),
    LL(0x838f8f068f0c8903), LL(0x044e4e254e4a6b9c), LL(0x66b7b7e6b7d15173), LL(0xe0ebeb8beb0b60cb),
    LL(0xc13c3cf03cfdcc78), LL(0xfd81813e817cbf1f), LL(0x4094946a94d4fe35), LL(0x1cf7f7fbf7eb0cf3),
    LL(0x18b9b9deb9a1676f), LL(0x8b13134c13985f26), LL(0x512c2cb02c7d9c58), LL(0x05d3d36bd3d6b8bb),
    LL(0x8ce7e7bbe76b5cd3), LL(0x396e6ea56e57cbdc), LL(0xaac4c437c46ef395), LL(0x1b03030c03180f06),
    LL(0xdc565645568a13ac), LL(0x5e44440d441a4988), LL(0xa07f7fe17fdf9efe), LL(0x88a9a99ea921374f),
    LL(0x672a2aa82a4d8254), LL(0x0abbbbd6bbb16d6b), LL(0x87c1c123c146e29f), LL(0xf153535153a202a6),
    LL(0x72dcdc57dcae8ba5), LL(0x530b0b2c0b582716), LL(0x019d9d4e9d9cd327), LL(0x2b6c6cad6c47c1d8),
    LL(0xa43131c43195f562), LL(0xf37474cd7487b9e8), LL(0x15f6f6fff6e309f1), LL(0x4c464605460a438c),
    LL(0xa5acac8aac092645), LL(0xb589891e893c970f), LL(0xb414145014a04428), LL(0xbae1e1a3e15b42df),
    LL(0xa616165816b04e2c), LL(0xf73a3ae83acdd274), LL(0x066969b9696fd0d2), LL(0x4109092409482d12),
    LL(0xd77070dd70a7ade0), LL(0x6fb6b6e2b6d95471), LL(0x1ed0d067d0ceb7bd), LL(0xd6eded93ed3b7ec7),
    LL(0xe2cccc17cc2edb85), LL(0x68424215422a5784), LL(0x2c98985a98b4c22d), LL(0xeda4a4aaa4490e55),
    LL(0x752828a0285d8850), LL(0x865c5c6d5cda31b8), LL(0x6bf8f8c7f8933fed), LL(0xc28686228644a411),

	LL(0x30d818186018c078), LL(0x462623238c2305af), LL(0x91b8c6c63fc67ef9), LL(0xcdfbe8e887e8136f),
    LL(0x13cb878726874ca1), LL(0x6d11b8b8dab8a962), LL(0x0209010104010805), LL(0x9e0d4f4f214f426e),
    LL(0x6c9b3636d836adee), LL(0x51ffa6a6a2a65904), LL(0xb90cd2d26fd2debd), LL(0xf70ef5f5f3f5fb06),
    LL(0xf2967979f979ef80), LL(0xde306f6fa16f5fce), LL(0x3f6d91917e91fcef), LL(0xa4f852525552aa07),
    LL(0xc04760609d6027fd), LL(0x6535bcbccabc8976), LL(0x2b379b9b569baccd), LL(0x018a8e8e028e048c),
    LL(0x5bd2a3a3b6a37115), LL(0x186c0c0c300c603c), LL(0xf6847b7bf17bff8a), LL(0x6a803535d435b5e1),
    LL(0x3af51d1d741de869), LL(0xddb3e0e0a7e05347), LL(0xb321d7d77bd7f6ac), LL(0x999cc2c22fc25eed),
    LL(0x5c432e2eb82e6d96), LL(0x96294b4b314b627a), LL(0xe15dfefedffea321), LL(0xaed5575741578216),
    LL(0x2abd15155415a841), LL(0xeee87777c1779fb6), LL(0x6e923737dc37a5eb), LL(0xd79ee5e5b3e57b56),
    LL(0x23139f9f469f8cd9), LL(0xfd23f0f0e7f0d317), LL(0x94204a4a354a6a7f), LL(0xa944dada4fda9e95),
    LL(0xb0a258587d58fa25), LL(0x8fcfc9c903c906ca), LL(0x527c2929a429558d), LL(0x145a0a0a280a5022),
    LL(0x7f50b1b1feb1e14f), LL(0x5dc9a0a0baa0691a), LL(0xd6146b6bb16b7fda), LL(0x17d985852e855cab),
    LL(0x673cbdbdcebd8173), LL(0xba8f5d5d695dd234), LL(0x2090101040108050), LL(0xf507f4f4f7f4f303),
    LL(0x8bddcbcb0bcb16c0), LL(0x7cd33e3ef83eedc6), LL(0x0a2d050514052811), LL(0xce78676781671fe6),
    LL(0xd597e4e4b7e47353), LL(0x4e0227279c2725bb), LL(0x8273414119413258), LL(0x0ba78b8b168b2c9d),
    LL(0x53f6a7a7a6a75101), LL(0xfab27d7de97dcf94), LL(0x374995956e95dcfb), LL(0xad56d8d847d88e9f),
    LL(0xeb70fbfbcbfb8b30), LL(0xc1cdeeee9fee2371), LL(0xf8bb7c7ced7cc791), LL(0xcc716666856617e3),
    LL(0xa77bdddd53dda68e), LL(0x2eaf17175c17b84b), LL(0x8e45474701470246), LL(0x211a9e9e429e84dc),
    LL(0x89d4caca0fca1ec5), LL(0x5a582d2db42d7599), LL(0x632ebfbfc6bf9179), LL(0x0e3f07071c07381b),
    LL(0x47acadad8ead0123), LL(0xb4b05a5a755aea2f), LL(0x1bef838336836cb5), LL(0x66b63333cc3385ff),
    LL(0xc65c636391633ff2), LL(0x041202020802100a), LL(0x4993aaaa92aa3938), LL(0xe2de7171d971afa8),
    LL(0x8dc6c8c807c80ecf), LL(0x32d119196419c87d), LL(0x923b494939497270), LL(0xaf5fd9d943d9869a),
    LL(0xf931f2f2eff2c31d), LL(0xdba8e3e3abe34b48), LL(0xb6b95b5b715be22a), LL(0x0dbc88881a883492),
    LL(0x293e9a9a529aa4c8), LL(0x4c0b262698262dbe), LL(0x64bf3232c8328dfa), LL(0x7d59b0b0fab0e94a),
    LL(0xcff2e9e983e91b6a), LL(0x1e770f0f3c0f7833), LL(0xb733d5d573d5e6a6), LL(0x1df480803a8074ba),
    LL(0x6127bebec2be997c), LL(0x87ebcdcd13cd26de), LL(0x68893434d034bde4), LL(0x903248483d487a75),
    LL(0xe354ffffdbffab24), LL(0xf48d7a7af57af78f), LL(0x3d6490907a90f4ea), LL(0xbe9d5f5f615fc23e),
    LL(0x403d202080201da0), LL(0xd00f6868bd6867d5), LL(0x34ca1a1a681ad072), LL(0x41b7aeae82ae192c),
    LL(0x757db4b4eab4c95e), LL(0xa8ce54544d549a19), LL(0x3b7f93937693ece5), LL(0x442f222288220daa),
    LL(0xc86364648d6407e9), LL(0xff2af1f1e3f1db12), LL(0xe6cc7373d173bfa2), LL(0x248212124812905a),
    LL(0x807a40401d403a5d), LL(0x1048080820084028), LL(0x9b95c3c32bc356e8), LL(0xc5dfecec97ec337b),
    LL(0xab4ddbdb4bdb9690), LL(0x5fc0a1a1bea1611f), LL(0x07918d8d0e8d1c83), LL(0x7ac83d3df43df5c9),
    LL(0x335b97976697ccf1), LL(0x0000000000000000), LL(0x83f9cfcf1bcf36d4), LL(0x566e2b2bac2b4587),
    LL(0xece17676c57697b3), LL(0x19e68282328264b0), LL(0xb128d6d67fd6fea9), LL(0x36c31b1b6c1bd877),
    LL(0x7774b5b5eeb5c15b), LL(0x43beafaf86af1129), LL(0xd41d6a6ab56a77df), LL(0xa0ea50505d50ba0d),
    LL(0x8a5745450945124c), LL(0xfb38f3f3ebf3cb18), LL(0x60ad3030c0309df0), LL(0xc3c4efef9bef2b74),
    LL(0x7eda3f3ffc3fe5c3), LL(0xaac755554955921c), LL(0x59dba2a2b2a27910), LL(0xc9e9eaea8fea0365),
    LL(0xca6a656589650fec), LL(0x6903babad2bab968), LL(0x5e4a2f2fbc2f6593), LL(0x9d8ec0c027c04ee7),
    LL(0xa160dede5fdebe81), LL(0x38fc1c1c701ce06c), LL(0xe746fdfdd3fdbb2e), LL(0x9a1f4d4d294d5264),
    LL(0x397692927292e4e0), LL(0xeafa7575c9758fbc), LL(0x0c3606061806301e), LL(0x09ae8a8a128a2498),
    LL(0x794bb2b2f2b2f940), LL(0xd185e6e6bfe66359), LL(0x1c7e0e0e380e7036), LL(0x3ee71f1f7c1ff863),
    LL(0xc4556262956237f7), LL(0xb53ad4d477d4eea3), LL(0x4d81a8a89aa82932), LL(0x315296966296c4f4),
    LL(0xef62f9f9c3f99b3a), LL(0x97a3c5c533c566f6), LL(0x4a102525942535b1), LL(0xb2ab59597959f220),
    LL(0x15d084842a8454ae), LL(0xe4c57272d572b7a7), LL(0x72ec3939e439d5dd), LL(0x98164c4c2d4c5a61),
    LL(0xbc945e5e655eca3b), LL(0xf09f7878fd78e785), LL(0x70e53838e038ddd8), LL(0x05988c8c0a8c1486),
    LL(0xbf17d1d163d1c6b2), LL(0x57e4a5a5aea5410b), LL(0xd9a1e2e2afe2434d), LL(0xc24e616199612ff8),
    LL(0x7b42b3b3f6b3f145), LL(0x42342121842115a5), LL(0x25089c9c4a9c94d6), LL(0x3cee1e1e781ef066),
    LL(0x8661434311432252), LL(0x93b1c7c73bc776fc), LL(0xe54ffcfcd7fcb32b), LL(0x0824040410042014),
    LL(0xa2e351515951b208), LL(0x2f2599995e99bcc7), LL(0xda226d6da96d4fc4), LL(0x1a650d0d340d6839),
    LL(0xe979fafacffa8335), LL(0xa369dfdf5bdfb684), LL(0xfca97e7ee57ed79b), LL(0x4819242490243db4),
    LL(0x76fe3b3bec3bc5d7), LL(0x4b9aabab96ab313d), LL(0x81f0cece1fce3ed1), LL(0x2299111144118855),
    LL(0x03838f8f068f0c89), LL(0x9c044e4e254e4a6b), LL(0x7366b7b7e6b7d151), LL(0xcbe0ebeb8beb0b60),
    LL(0x78c13c3cf03cfdcc), LL(0x1ffd81813e817cbf), LL(0x354094946a94d4fe), LL(0xf31cf7f7fbf7eb0c),
    LL(0x6f18b9b9deb9a167), LL(0x268b13134c13985f), LL(0x58512c2cb02c7d9c), LL(0xbb05d3d36bd3d6b8),
    LL(0xd38ce7e7bbe76b5c), LL(0xdc396e6ea56e57cb), LL(0x95aac4c437c46ef3), LL(0x061b03030c03180f),
    LL(0xacdc565645568a13), LL(0x885e44440d441a49), LL(0xfea07f7fe17fdf9e), LL(0x4f88a9a99ea92137),
    LL(0x54672a2aa82a4d82), LL(0x6b0abbbbd6bbb16d), LL(0x9f87c1c123c146e2), LL(0xa6f153535153a202),
    LL(0xa572dcdc57dcae8b), LL(0x16530b0b2c0b5827), LL(0x27019d9d4e9d9cd3), LL(0xd82b6c6cad6c47c1),
    LL(0x62a43131c43195f5), LL(0xe8f37474cd7487b9), LL(0xf115f6f6fff6e309), LL(0x8c4c464605460a43),
    LL(0x45a5acac8aac0926), LL(0x0fb589891e893c97), LL(0x28b414145014a044), LL(0xdfbae1e1a3e15b42),
    LL(0x2ca616165816b04e), LL(0x74f73a3ae83acdd2), LL(0xd2066969b9696fd0), LL(0x124109092409482d),
    LL(0xe0d77070dd70a7ad), LL(0x716fb6b6e2b6d954), LL(0xbd1ed0d067d0ceb7), LL(0xc7d6eded93ed3b7e),
    LL(0x85e2cccc17cc2edb), LL(0x8468424215422a57), LL(0x2d2c98985a98b4c2), LL(0x55eda4a4aaa4490e),
    LL(0x50752828a0285d88), LL(0xb8865c5c6d5cda31), LL(0xed6bf8f8c7f8933f), LL(0x11c28686228644a4),

	LL(0x7830d818186018c0), LL(0xaf462623238c2305), LL(0xf991b8c6c63fc67e), LL(0x6fcdfbe8e887e813),
    LL(0xa113cb878726874c), LL(0x626d11b8b8dab8a9), LL(0x0502090101040108), LL(0x6e9e0d4f4f214f42),
    LL(0xee6c9b3636d836ad), LL(0x0451ffa6a6a2a659), LL(0xbdb90cd2d26fd2de), LL(0x06f70ef5f5f3f5fb),
    LL(0x80f2967979f979ef), LL(0xcede306f6fa16f5f), LL(0xef3f6d91917e91fc), LL(0x07a4f852525552aa),
    LL(0xfdc04760609d6027), LL(0x766535bcbccabc89), LL(0xcd2b379b9b569bac), LL(0x8c018a8e8e028e04),
    LL(0x155bd2a3a3b6a371), LL(0x3c186c0c0c300c60), LL(0x8af6847b7bf17bff), LL(0xe16a803535d435b5),
    LL(0x693af51d1d741de8), LL(0x47ddb3e0e0a7e053), LL(0xacb321d7d77bd7f6), LL(0xed999cc2c22fc25e),
    LL(0x965c432e2eb82e6d), LL(0x7a96294b4b314b62), LL(0x21e15dfefedffea3), LL(0x16aed55757415782),
    LL(0x412abd15155415a8), LL(0xb6eee87777c1779f), LL(0xeb6e923737dc37a5), LL(0x56d79ee5e5b3e57b),
    LL(0xd923139f9f469f8c), LL(0x17fd23f0f0e7f0d3), LL(0x7f94204a4a354a6a), LL(0x95a944dada4fda9e),
    LL(0x25b0a258587d58fa), LL(0xca8fcfc9c903c906), LL(0x8d527c2929a42955), LL(0x22145a0a0a280a50),
    LL(0x4f7f50b1b1feb1e1), LL(0x1a5dc9a0a0baa069), LL(0xdad6146b6bb16b7f), LL(0xab17d985852e855c),
    LL(0x73673cbdbdcebd81), LL(0x34ba8f5d5d695dd2), LL(0x5020901010401080), LL(0x03f507f4f4f7f4f3),
    LL(0xc08bddcbcb0bcb16), LL(0xc67cd33e3ef83eed), LL(0x110a2d0505140528), LL(0xe6ce78676781671f),
    LL(0x53d597e4e4b7e473), LL(0xbb4e0227279c2725), LL(0x5882734141194132), LL(0x9d0ba78b8b168b2c),
    LL(0x0153f6a7a7a6a751), LL(0x94fab27d7de97dcf), LL(0xfb374995956e95dc), LL(0x9fad56d8d847d88e),
    LL(0x30eb70fbfbcbfb8b), LL(0x71c1cdeeee9fee23), LL(0x91f8bb7c7ced7cc7), LL(0xe3cc716666856617),
    LL(0x8ea77bdddd53dda6), LL(0x4b2eaf17175c17b8), LL(0x468e454747014702), LL(0xdc211a9e9e429e84),
    LL(0xc589d4caca0fca1e), LL(0x995a582d2db42d75), LL(0x79632ebfbfc6bf91), LL(0x1b0e3f07071c0738),
    LL(0x2347acadad8ead01), LL(0x2fb4b05a5a755aea), LL(0xb51bef838336836c), LL(0xff66b63333cc3385),
    LL(0xf2c65c636391633f), LL(0x0a04120202080210), LL(0x384993aaaa92aa39), LL(0xa8e2de7171d971af),
    LL(0xcf8dc6c8c807c80e), LL(0x7d32d119196419c8), LL(0x70923b4949394972), LL(0x9aaf5fd9d943d986),
    LL(0x1df931f2f2eff2c3), LL(0x48dba8e3e3abe34b), LL(0x2ab6b95b5b715be2), LL(0x920dbc88881a8834),
    LL(0xc8293e9a9a529aa4), LL(0xbe4c0b262698262d), LL(0xfa64bf3232c8328d), LL(0x4a7d59b0b0fab0e9),
    LL(0x6acff2e9e983e91b), LL(0x331e770f0f3c0f78), LL(0xa6b733d5d573d5e6), LL(0xba1df480803a8074),
    LL(0x7c6127bebec2be99), LL(0xde87ebcdcd13cd26), LL(0xe468893434d034bd), LL(0x75903248483d487a),
    LL(0x24e354ffffdbffab), LL(0x8ff48d7a7af57af7), LL(0xea3d6490907a90f4), LL(0x3ebe9d5f5f615fc2),
    LL(0xa0403d202080201d), LL(0xd5d00f6868bd6867), LL(0x7234ca1a1a681ad0), LL(0x2c41b7aeae82ae19),
    LL(0x5e757db4b4eab4c9), LL(0x19a8ce54544d549a), LL(0xe53b7f93937693ec), LL(0xaa442f222288220d),
    LL(0xe9c86364648d6407), LL(0x12ff2af1f1e3f1db), LL(0xa2e6cc7373d173bf), LL(0x5a24821212481290),
    LL(0x5d807a40401d403a), LL(0x2810480808200840), LL(0xe89b95c3c32bc356), LL(0x7bc5dfecec97ec33),
    LL(0x90ab4ddbdb4bdb96), LL(0x1f5fc0a1a1bea161), LL(0x8307918d8d0e8d1c), LL(0xc97ac83d3df43df5),
    LL(0xf1335b97976697cc), LL(0x0000000000000000), LL(0xd483f9cfcf1bcf36), LL(0x87566e2b2bac2b45),
    LL(0xb3ece17676c57697), LL(0xb019e68282328264), LL(0xa9b128d6d67fd6fe), LL(0x7736c31b1b6c1bd8),
    LL(0x5b7774b5b5eeb5c1), LL(0x2943beafaf86af11), LL(0xdfd41d6a6ab56a77), LL(0x0da0ea50505d50ba),
    LL(0x4c8a574545094512), LL(0x18fb38f3f3ebf3cb), LL(0xf060ad3030c0309d), LL(0x74c3c4efef9bef2b),
    LL(0xc37eda3f3ffc3fe5), LL(0x1caac75555495592), LL(0x1059dba2a2b2a279), LL(0x65c9e9eaea8fea03),
    LL(0xecca6a656589650f), LL(0x686903babad2bab9), LL(0x935e4a2f2fbc2f65), LL(0xe79d8ec0c027c04e),
    LL(0x81a160dede5fdebe), LL(0x6c38fc1c1c701ce0), LL(0x2ee746fdfdd3fdbb), LL(0x649a1f4d4d294d52),
    LL(0xe0397692927292e4), LL(0xbceafa7575c9758f), LL(0x1e0c360606180630), LL(0x9809ae8a8a128a24),
    LL(0x40794bb2b2f2b2f9), LL(0x59d185e6e6bfe663), LL(0x361c7e0e0e380e70), LL(0x633ee71f1f7c1ff8),
    LL(0xf7c4556262956237), LL(0xa3b53ad4d477d4ee), LL(0x324d81a8a89aa829), LL(0xf4315296966296c4),
    LL(0x3aef62f9f9c3f99b), LL(0xf697a3c5c533c566), LL(0xb14a102525942535), LL(0x20b2ab59597959f2),
    LL(0xae15d084842a8454), LL(0xa7e4c57272d572b7), LL(0xdd72ec3939e439d5), LL(0x6198164c4c2d4c5a),
    LL(0x3bbc945e5e655eca), LL(0x85f09f7878fd78e7), LL(0xd870e53838e038dd), LL(0x8605988c8c0a8c14),
    LL(0xb2bf17d1d163d1c6), LL(0x0b57e4a5a5aea541), LL(0x4dd9a1e2e2afe243), LL(0xf8c24e616199612f),
    LL(0x457b42b3b3f6b3f1), LL(0xa542342121842115), LL(0xd625089c9c4a9c94), LL(0x663cee1e1e781ef0),
    LL(0x5286614343114322), LL(0xfc93b1c7c73bc776), LL(0x2be54ffcfcd7fcb3), LL(0x1408240404100420),
    LL(0x08a2e351515951b2), LL(0xc72f2599995e99bc), LL(0xc4da226d6da96d4f), LL(0x391a650d0d340d68),
    LL(0x35e979fafacffa83), LL(0x84a369dfdf5bdfb6), LL(0x9bfca97e7ee57ed7), LL(0xb44819242490243d),
    LL(0xd776fe3b3bec3bc5), LL(0x3d4b9aabab96ab31), LL(0xd181f0cece1fce3e), LL(0x5522991111441188),
    LL(0x8903838f8f068f0c), LL(0x6b9c044e4e254e4a), LL(0x517366b7b7e6b7d1), LL(0x60cbe0ebeb8beb0b),
    LL(0xcc78c13c3cf03cfd), LL(0xbf1ffd81813e817c), LL(0xfe354094946a94d4), LL(0x0cf31cf7f7fbf7eb),
    LL(0x676f18b9b9deb9a1), LL(0x5f268b13134c1398), LL(0x9c58512c2cb02c7d), LL(0xb8bb05d3d36bd3d6),
    LL(0x5cd38ce7e7bbe76b), LL(0xcbdc396e6ea56e57), LL(0xf395aac4c437c46e), LL(0x0f061b03030c0318),
    LL(0x13acdc565645568a), LL(0x49885e44440d441a), LL(0x9efea07f7fe17fdf), LL(0x374f88a9a99ea921),
    LL(0x8254672a2aa82a4d), LL(0x6d6b0abbbbd6bbb1), LL(0xe29f87c1c123c146), LL(0x02a6f153535153a2),
    LL(0x8ba572dcdc57dcae), LL(0x2716530b0b2c0b58), LL(0xd327019d9d4e9d9c), LL(0xc1d82b6c6cad6c47),
    LL(0xf562a43131c43195), LL(0xb9e8f37474cd7487), LL(0x09f115f6f6fff6e3), LL(0x438c4c464605460a),
    LL(0x2645a5acac8aac09), LL(0x970fb589891e893c), LL(0x4428b414145014a0), LL(0x42dfbae1e1a3e15b),
    LL(0x4e2ca616165816b0), LL(0xd274f73a3ae83acd), LL(0xd0d2066969b9696f), LL(0x2d12410909240948),
    LL(0xade0d77070dd70a7), LL(0x54716fb6b6e2b6d9), LL(0xb7bd1ed0d067d0ce), LL(0x7ec7d6eded93ed3b),
    LL(0xdb85e2cccc17cc2e), LL(0x578468424215422a), LL(0xc22d2c98985a98b4), LL(0x0e55eda4a4aaa449),
    LL(0x8850752828a0285d), LL(0x31b8865c5c6d5cda), LL(0x3fed6bf8f8c7f893), LL(0xa411c28686228644),

    LL(0xc07830d818186018), LL(0x05af462623238c23), LL(0x7ef991b8c6c63fc6), LL(0x136fcdfbe8e887e8),
    LL(0x4ca113cb87872687), LL(0xa9626d11b8b8dab8), LL(0x0805020901010401), LL(0x426e9e0d4f4f214f),
    LL(0xadee6c9b3636d836), LL(0x590451ffa6a6a2a6), LL(0xdebdb90cd2d26fd2), LL(0xfb06f70ef5f5f3f5),
    LL(0xef80f2967979f979), LL(0x5fcede306f6fa16f), LL(0xfcef3f6d91917e91), LL(0xaa07a4f852525552),
    LL(0x27fdc04760609d60), LL(0x89766535bcbccabc), LL(0xaccd2b379b9b569b), LL(0x048c018a8e8e028e),
    LL(0x71155bd2a3a3b6a3), LL(0x603c186c0c0c300c), LL(0xff8af6847b7bf17b), LL(0xb5e16a803535d435),
    LL(0xe8693af51d1d741d), LL(0x5347ddb3e0e0a7e0), LL(0xf6acb321d7d77bd7), LL(0x5eed999cc2c22fc2),
    LL(0x6d965c432e2eb82e), LL(0x627a96294b4b314b), LL(0xa321e15dfefedffe), LL(0x8216aed557574157),
    LL(0xa8412abd15155415), LL(0x9fb6eee87777c177), LL(0xa5eb6e923737dc37), LL(0x7b56d79ee5e5b3e5),
    LL(0x8cd923139f9f469f), LL(0xd317fd23f0f0e7f0), LL(0x6a7f94204a4a354a), LL(0x9e95a944dada4fda),
    LL(0xfa25b0a258587d58), LL(0x06ca8fcfc9c903c9), LL(0x558d527c2929a429), LL(0x5022145a0a0a280a),
    LL(0xe14f7f50b1b1feb1), LL(0x691a5dc9a0a0baa0), LL(0x7fdad6146b6bb16b), LL(0x5cab17d985852e85),
    LL(0x8173673cbdbdcebd), LL(0xd234ba8f5d5d695d), LL(0x8050209010104010), LL(0xf303f507f4f4f7f4),
    LL(0x16c08bddcbcb0bcb), LL(0xedc67cd33e3ef83e), LL(0x28110a2d05051405), LL(0x1fe6ce7867678167),
    LL(0x7353d597e4e4b7e4), LL(0x25bb4e0227279c27), LL(0x3258827341411941), LL(0x2c9d0ba78b8b168b),
    LL(0x510153f6a7a7a6a7), LL(0xcf94fab27d7de97d), LL(0xdcfb374995956e95), LL(0x8e9fad56d8d847d8),
    LL(0x8b30eb70fbfbcbfb), LL(0x2371c1cdeeee9fee), LL(0xc791f8bb7c7ced7c), LL(0x17e3cc7166668566),
    LL(0xa68ea77bdddd53dd), LL(0xb84b2eaf17175c17), LL(0x02468e4547470147), LL(0x84dc211a9e9e429e),
    LL(0x1ec589d4caca0fca), LL(0x75995a582d2db42d), LL(0x9179632ebfbfc6bf), LL(0x381b0e3f07071c07),
    LL(0x012347acadad8ead), LL(0xea2fb4b05a5a755a), LL(0x6cb51bef83833683), LL(0x85ff66b63333cc33),
    LL(0x3ff2c65c63639163), LL(0x100a041202020802), LL(0x39384993aaaa92aa), LL(0xafa8e2de7171d971),
    LL(0x0ecf8dc6c8c807c8), LL(0xc87d32d119196419), LL(0x7270923b49493949), LL(0x869aaf5fd9d943d9),
    LL(0xc31df931f2f2eff2), LL(0x4b48dba8e3e3abe3), LL(0xe22ab6b95b5b715b), LL(0x34920dbc88881a88),
    LL(0xa4c8293e9a9a529a), LL(0x2dbe4c0b26269826), LL(0x8dfa64bf3232c832), LL(0xe94a7d59b0b0fab0),
    LL(0x1b6acff2e9e983e9), LL(0x78331e770f0f3c0f), LL(0xe6a6b733d5d573d5), LL(0x74ba1df480803a80),
    LL(0x997c6127bebec2be), LL(0x26de87ebcdcd13cd), LL(0xbde468893434d034), LL(0x7a75903248483d48),
    LL(0xab24e354ffffdbff), LL(0xf78ff48d7a7af57a), LL(0xf4ea3d6490907a90), LL(0xc23ebe9d5f5f615f),
    LL(0x1da0403d20208020), LL(0x67d5d00f6868bd68), LL(0xd07234ca1a1a681a), LL(0x192c41b7aeae82ae),
    LL(0xc95e757db4b4eab4), LL(0x9a19a8ce54544d54), LL(0xece53b7f93937693), LL(0x0daa442f22228822),
    LL(0x07e9c86364648d64), LL(0xdb12ff2af1f1e3f1), LL(0xbfa2e6cc7373d173), LL(0x905a248212124812),
    LL(0x3a5d807a40401d40), LL(0x4028104808082008), LL(0x56e89b95c3c32bc3), LL(0x337bc5dfecec97ec),
    LL(0x9690ab4ddbdb4bdb), LL(0x611f5fc0a1a1bea1), LL(0x1c8307918d8d0e8d), LL(0xf5c97ac83d3df43d),
    LL(0xccf1335b97976697), LL(0x0000000000000000), LL(0x36d483f9cfcf1bcf), LL(0x4587566e2b2bac2b),
    LL(0x97b3ece17676c576), LL(0x64b019e682823282), LL(0xfea9b128d6d67fd6), LL(0xd87736c31b1b6c1b),
    LL(0xc15b7774b5b5eeb5), LL(0x112943beafaf86af), LL(0x77dfd41d6a6ab56a), LL(0xba0da0ea50505d50),
    LL(0x124c8a5745450945), LL(0xcb18fb38f3f3ebf3), LL(0x9df060ad3030c030), LL(0x2b74c3c4efef9bef),
    LL(0xe5c37eda3f3ffc3f), LL(0x921caac755554955), LL(0x791059dba2a2b2a2), LL(0x0365c9e9eaea8fea),
    LL(0x0fecca6a65658965), LL(0xb9686903babad2ba), LL(0x65935e4a2f2fbc2f), LL(0x4ee79d8ec0c027c0),
    LL(0xbe81a160dede5fde), LL(0xe06c38fc1c1c701c), LL(0xbb2ee746fdfdd3fd), LL(0x52649a1f4d4d294d),
    LL(0xe4e0397692927292), LL(0x8fbceafa7575c975), LL(0x301e0c3606061806), LL(0x249809ae8a8a128a),
    LL(0xf940794bb2b2f2b2), LL(0x6359d185e6e6bfe6), LL(0x70361c7e0e0e380e), LL(0xf8633ee71f1f7c1f),
    LL(0x37f7c45562629562), LL(0xeea3b53ad4d477d4), LL(0x29324d81a8a89aa8), LL(0xc4f4315296966296),
    LL(0x9b3aef62f9f9c3f9), LL(0x66f697a3c5c533c5), LL(0x35b14a1025259425), LL(0xf220b2ab59597959),
    LL(0x54ae15d084842a84), LL(0xb7a7e4c57272d572), LL(0xd5dd72ec3939e439), LL(0x5a6198164c4c2d4c),
    LL(0xca3bbc945e5e655e), LL(0xe785f09f7878fd78), LL(0xddd870e53838e038), LL(0x148605988c8c0a8c),
    LL(0xc6b2bf17d1d163d1), LL(0x410b57e4a5a5aea5), LL(0x434dd9a1e2e2afe2), LL(0x2ff8c24e61619961),
    LL(0xf1457b42b3b3f6b3), LL(0x15a5423421218421), LL(0x94d625089c9c4a9c), LL(0xf0663cee1e1e781e),
    LL(0x2252866143431143), LL(0x76fc93b1c7c73bc7), LL(0xb32be54ffcfcd7fc), LL(0x2014082404041004),
    LL(0xb208a2e351515951), LL(0xbcc72f2599995e99), LL(0x4fc4da226d6da96d), LL(0x68391a650d0d340d),
    LL(0x8335e979fafacffa), LL(0xb684a369dfdf5bdf), LL(0xd79bfca97e7ee57e), LL(0x3db4481924249024),
    LL(0xc5d776fe3b3bec3b), LL(0x313d4b9aabab96ab), LL(0x3ed181f0cece1fce), LL(0x8855229911114411),
    LL(0x0c8903838f8f068f), LL(0x4a6b9c044e4e254e), LL(0xd1517366b7b7e6b7), LL(0x0b60cbe0ebeb8beb),
    LL(0xfdcc78c13c3cf03c), LL(0x7cbf1ffd81813e81), LL(0xd4fe354094946a94), LL(0xeb0cf31cf7f7fbf7),
    LL(0xa1676f18b9b9deb9), LL(0x985f268b13134c13), LL(0x7d9c58512c2cb02c), LL(0xd6b8bb05d3d36bd3),
    LL(0x6b5cd38ce7e7bbe7), LL(0x57cbdc396e6ea56e), LL(0x6ef395aac4c437c4), LL(0x180f061b03030c03),
    LL(0x8a13acdc56564556), LL(0x1a49885e44440d44), LL(0xdf9efea07f7fe17f), LL(0x21374f88a9a99ea9),
    LL(0x4d8254672a2aa82a), LL(0xb16d6b0abbbbd6bb), LL(0x46e29f87c1c123c1), LL(0xa202a6f153535153),
    LL(0xae8ba572dcdc57dc), LL(0x582716530b0b2c0b), LL(0x9cd327019d9d4e9d), LL(0x47c1d82b6c6cad6c),
    LL(0x95f562a43131c431), LL(0x87b9e8f37474cd74), LL(0xe309f115f6f6fff6), LL(0x0a438c4c46460546),
    LL(0x092645a5acac8aac), LL(0x3c970fb589891e89), LL(0xa04428b414145014), LL(0x5b42dfbae1e1a3e1),
    LL(0xb04e2ca616165816), LL(0xcdd274f73a3ae83a), LL(0x6fd0d2066969b969), LL(0x482d124109092409),
    LL(0xa7ade0d77070dd70), LL(0xd954716fb6b6e2b6), LL(0xceb7bd1ed0d067d0), LL(0x3b7ec7d6eded93ed),
    LL(0x2edb85e2cccc17cc), LL(0x2a57846842421542), LL(0xb4c22d2c98985a98), LL(0x490e55eda4a4aaa4),
    LL(0x5d8850752828a028), LL(0xda31b8865c5c6d5c), LL(0x933fed6bf8f8c7f8), LL(0x44a411c286862286),

    LL(0x18c07830d8181860), LL(0x2305af462623238c), LL(0xc67ef991b8c6c63f), LL(0xe8136fcdfbe8e887),
    LL(0x874ca113cb878726), LL(0xb8a9626d11b8b8da), LL(0x0108050209010104), LL(0x4f426e9e0d4f4f21),
    LL(0x36adee6c9b3636d8), LL(0xa6590451ffa6a6a2), LL(0xd2debdb90cd2d26f), LL(0xf5fb06f70ef5f5f3),
    LL(0x79ef80f2967979f9), LL(0x6f5fcede306f6fa1), LL(0x91fcef3f6d91917e), LL(0x52aa07a4f8525255),
    LL(0x6027fdc04760609d), LL(0xbc89766535bcbcca), LL(0x9baccd2b379b9b56), LL(0x8e048c018a8e8e02),
    LL(0xa371155bd2a3a3b6), LL(0x0c603c186c0c0c30), LL(0x7bff8af6847b7bf1), LL(0x35b5e16a803535d4),
    LL(0x1de8693af51d1d74), LL(0xe05347ddb3e0e0a7), LL(0xd7f6acb321d7d77b), LL(0xc25eed999cc2c22f),
    LL(0x2e6d965c432e2eb8), LL(0x4b627a96294b4b31), LL(0xfea321e15dfefedf), LL(0x578216aed5575741),
    LL(0x15a8412abd151554), LL(0x779fb6eee87777c1), LL(0x37a5eb6e923737dc), LL(0xe57b56d79ee5e5b3),
    LL(0x9f8cd923139f9f46), LL(0xf0d317fd23f0f0e7), LL(0x4a6a7f94204a4a35), LL(0xda9e95a944dada4f),
    LL(0x58fa25b0a258587d), LL(0xc906ca8fcfc9c903), LL(0x29558d527c2929a4), LL(0x0a5022145a0a0a28),
    LL(0xb1e14f7f50b1b1fe), LL(0xa0691a5dc9a0a0ba), LL(0x6b7fdad6146b6bb1), LL(0x855cab17d985852e),
    LL(0xbd8173673cbdbdce), LL(0x5dd234ba8f5d5d69), LL(0x1080502090101040), LL(0xf4f303f507f4f4f7),
    LL(0xcb16c08bddcbcb0b), LL(0x3eedc67cd33e3ef8), LL(0x0528110a2d050514), LL(0x671fe6ce78676781),
    LL(0xe47353d597e4e4b7), LL(0x2725bb4e0227279c), LL(0x4132588273414119), LL(0x8b2c9d0ba78b8b16),
    LL(0xa7510153f6a7a7a6), LL(0x7dcf94fab27d7de9), LL(0x95dcfb374995956e), LL(0xd88e9fad56d8d847),
    LL(0xfb8b30eb70fbfbcb), LL(0xee2371c1cdeeee9f), LL(0x7cc791f8bb7c7ced), LL(0x6617e3cc71666685),
    LL(0xdda68ea77bdddd53), LL(0x17b84b2eaf17175c), LL(0x4702468e45474701), LL(0x9e84dc211a9e9e42),
    LL(0xca1ec589d4caca0f), LL(0x2d75995a582d2db4), LL(0xbf9179632ebfbfc6), LL(0x07381b0e3f07071c),
    LL(0xad012347acadad8e), LL(0x5aea2fb4b05a5a75), LL(0x836cb51bef838336), LL(0x3385ff66b63333cc),
    LL(0x633ff2c65c636391), LL(0x02100a0412020208), LL(0xaa39384993aaaa92), LL(0x71afa8e2de7171d9),
    LL(0xc80ecf8dc6c8c807), LL(0x19c87d32d1191964), LL(0x497270923b494939), LL(0xd9869aaf5fd9d943),
    LL(0xf2c31df931f2f2ef), LL(0xe34b48dba8e3e3ab), LL(0x5be22ab6b95b5b71), LL(0x8834920dbc88881a),
    LL(0x9aa4c8293e9a9a52), LL(0x262dbe4c0b262698), LL(0x328dfa64bf3232c8), LL(0xb0e94a7d59b0b0fa),
    LL(0xe91b6acff2e9e983), LL(0x0f78331e770f0f3c), LL(0xd5e6a6b733d5d573), LL(0x8074ba1df480803a),
    LL(0xbe997c6127bebec2), LL(0xcd26de87ebcdcd13), LL(0x34bde468893434d0), LL(0x487a75903248483d),
    LL(0xffab24e354ffffdb), LL(0x7af78ff48d7a7af5), LL(0x90f4ea3d6490907a), LL(0x5fc23ebe9d5f5f61),
    LL(0x201da0403d202080), LL(0x6867d5d00f6868bd), LL(0x1ad07234ca1a1a68), LL(0xae192c41b7aeae82),
    LL(0xb4c95e757db4b4ea), LL(0x549a19a8ce54544d), LL(0x93ece53b7f939376), LL(0x220daa442f222288),
    LL(0x6407e9c86364648d), LL(0xf1db12ff2af1f1e3), LL(0x73bfa2e6cc7373d1), LL(0x12905a2482121248),
    LL(0x403a5d807a40401d), LL(0x0840281048080820), LL(0xc356e89b95c3c32b), LL(0xec337bc5dfecec97),
    LL(0xdb9690ab4ddbdb4b), LL(0xa1611f5fc0a1a1be), LL(0x8d1c8307918d8d0e), LL(0x3df5c97ac83d3df4),
    LL(0x97ccf1335b979766), LL(0x0000000000000000), LL(0xcf36d483f9cfcf1b), LL(0x2b4587566e2b2bac),
    LL(0x7697b3ece17676c5), LL(0x8264b019e6828232), LL(0xd6fea9b128d6d67f), LL(0x1bd87736c31b1b6c),
    LL(0xb5c15b7774b5b5ee), LL(0xaf112943beafaf86), LL(0x6a77dfd41d6a6ab5), LL(0x50ba0da0ea50505d),
    LL(0x45124c8a57454509), LL(0xf3cb18fb38f3f3eb), LL(0x309df060ad3030c0), LL(0xef2b74c3c4efef9b),
    LL(0x3fe5c37eda3f3ffc), LL(0x55921caac7555549), LL(0xa2791059dba2a2b2), LL(0xea0365c9e9eaea8f),
    LL(0x650fecca6a656589), LL(0xbab9686903babad2), LL(0x2f65935e4a2f2fbc), LL(0xc04ee79d8ec0c027),
    LL(0xdebe81a160dede5f), LL(0x1ce06c38fc1c1c70), LL(0xfdbb2ee746fdfdd3), LL(0x4d52649a1f4d4d29),
    LL(0x92e4e03976929272), LL(0x758fbceafa7575c9), LL(0x06301e0c36060618), LL(0x8a249809ae8a8a12),
    LL(0xb2f940794bb2b2f2), LL(0xe66359d185e6e6bf), LL(0x0e70361c7e0e0e38), LL(0x1ff8633ee71f1f7c),
    LL(0x6237f7c455626295), LL(0xd4eea3b53ad4d477), LL(0xa829324d81a8a89a), LL(0x96c4f43152969662),
    LL(0xf99b3aef62f9f9c3), LL(0xc566f697a3c5c533), LL(0x2535b14a10252594), LL(0x59f220b2ab595979),
    LL(0x8454ae15d084842a), LL(0x72b7a7e4c57272d5), LL(0x39d5dd72ec3939e4), LL(0x4c5a6198164c4c2d),
    LL(0x5eca3bbc945e5e65), LL(0x78e785f09f7878fd), LL(0x38ddd870e53838e0), LL(0x8c148605988c8c0a),
    LL(0xd1c6b2bf17d1d163), LL(0xa5410b57e4a5a5ae), LL(0xe2434dd9a1e2e2af), LL(0x612ff8c24e616199),
    LL(0xb3f1457b42b3b3f6), LL(0x2115a54234212184), LL(0x9c94d625089c9c4a), LL(0x1ef0663cee1e1e78),
    LL(0x4322528661434311), LL(0xc776fc93b1c7c73b), LL(0xfcb32be54ffcfcd7), LL(0x0420140824040410),
    LL(0x51b208a2e3515159), LL(0x99bcc72f2599995e), LL(0x6d4fc4da226d6da9), LL(0x0d68391a650d0d34),
    LL(0xfa8335e979fafacf), LL(0xdfb684a369dfdf5b), LL(0x7ed79bfca97e7ee5), LL(0x243db44819242490),
    LL(0x3bc5d776fe3b3bec), LL(0xab313d4b9aabab96), LL(0xce3ed181f0cece1f), LL(0x1188552299111144),
    LL(0x8f0c8903838f8f06), LL(0x4e4a6b9c044e4e25), LL(0xb7d1517366b7b7e6), LL(0xeb0b60cbe0ebeb8b),
    LL(0x3cfdcc78c13c3cf0), LL(0x817cbf1ffd81813e), LL(0x94d4fe354094946a), LL(0xf7eb0cf31cf7f7fb),
    LL(0xb9a1676f18b9b9de), LL(0x13985f268b13134c), LL(0x2c7d9c58512c2cb0), LL(0xd3d6b8bb05d3d36b),
    LL(0xe76b5cd38ce7e7bb), LL(0x6e57cbdc396e6ea5), LL(0xc46ef395aac4c437), LL(0x03180f061b03030c),
    LL(0x568a13acdc565645), LL(0x441a49885e44440d), LL(0x7fdf9efea07f7fe1), LL(0xa921374f88a9a99e),
    LL(0x2a4d8254672a2aa8), LL(0xbbb16d6b0abbbbd6), LL(0xc146e29f87c1c123), LL(0x53a202a6f1535351),
    LL(0xdcae8ba572dcdc57), LL(0x0b582716530b0b2c), LL(0x9d9cd327019d9d4e), LL(0x6c47c1d82b6c6cad),
    LL(0x3195f562a43131c4), LL(0x7487b9e8f37474cd), LL(0xf6e309f115f6f6ff), LL(0x460a438c4c464605),
    LL(0xac092645a5acac8a), LL(0x893c970fb589891e), LL(0x14a04428b4141450), LL(0xe15b42dfbae1e1a3),
    LL(0x16b04e2ca6161658), LL(0x3acdd274f73a3ae8), LL(0x696fd0d2066969b9), LL(0x09482d1241090924),
    LL(0x70a7ade0d77070dd), LL(0xb6d954716fb6b6e2), LL(0xd0ceb7bd1ed0d067), LL(0xed3b7ec7d6eded93),
    LL(0xcc2edb85e2cccc17), LL(0x422a578468424215), LL(0x98b4c22d2c98985a), LL(0xa4490e55eda4a4aa),
    LL(0x285d8850752828a0), LL(0x5cda31b8865c5c6d), LL(0xf8933fed6bf8f8c7), LL(0x8644a411c2868622),

    LL(0x6018c07830d81818), LL(0x8c2305af46262323), LL(0x3fc67ef991b8c6c6), LL(0x87e8136fcdfbe8e8),
    LL(0x26874ca113cb8787), LL(0xdab8a9626d11b8b8), LL(0x0401080502090101), LL(0x214f426e9e0d4f4f),
    LL(0xd836adee6c9b3636), LL(0xa2a6590451ffa6a6), LL(0x6fd2debdb90cd2d2), LL(0xf3f5fb06f70ef5f5),
    LL(0xf979ef80f2967979), LL(0xa16f5fcede306f6f), LL(0x7e91fcef3f6d9191), LL(0x5552aa07a4f85252),
    LL(0x9d6027fdc0476060), LL(0xcabc89766535bcbc), LL(0x569baccd2b379b9b), LL(0x028e048c018a8e8e),
    LL(0xb6a371155bd2a3a3), LL(0x300c603c186c0c0c), LL(0xf17bff8af6847b7b), LL(0xd435b5e16a803535),
    LL(0x741de8693af51d1d), LL(0xa7e05347ddb3e0e0), LL(0x7bd7f6acb321d7d7), LL(0x2fc25eed999cc2c2),
    LL(0xb82e6d965c432e2e), LL(0x314b627a96294b4b), LL(0xdffea321e15dfefe), LL(0x41578216aed55757),
    LL(0x5415a8412abd1515), LL(0xc1779fb6eee87777), LL(0xdc37a5eb6e923737), LL(0xb3e57b56d79ee5e5),
    LL(0x469f8cd923139f9f), LL(0xe7f0d317fd23f0f0), LL(0x354a6a7f94204a4a), LL(0x4fda9e95a944dada),
    LL(0x7d58fa25b0a25858), LL(0x03c906ca8fcfc9c9), LL(0xa429558d527c2929), LL(0x280a5022145a0a0a),
    LL(0xfeb1e14f7f50b1b1), LL(0xbaa0691a5dc9a0a0), LL(0xb16b7fdad6146b6b), LL(0x2e855cab17d98585),
    LL(0xcebd8173673cbdbd), LL(0x695dd234ba8f5d5d), LL(0x4010805020901010), LL(0xf7f4f303f507f4f4),
    LL(0x0bcb16c08bddcbcb), LL(0xf83eedc67cd33e3e), LL(0x140528110a2d0505), LL(0x81671fe6ce786767),
    LL(0xb7e47353d597e4e4), LL(0x9c2725bb4e022727), LL(0x1941325882734141), LL(0x168b2c9d0ba78b8b),
    LL(0xa6a7510153f6a7a7), LL(0xe97dcf94fab27d7d), LL(0x6e95dcfb37499595), LL(0x47d88e9fad56d8d8),
    LL(0xcbfb8b30eb70fbfb), LL(0x9fee2371c1cdeeee), LL(0xed7cc791f8bb7c7c), LL(0x856617e3cc716666),
    LL(0x53dda68ea77bdddd), LL(0x5c17b84b2eaf1717), LL(0x014702468e454747), LL(0x429e84dc211a9e9e),
    LL(0x0fca1ec589d4caca), LL(0xb42d75995a582d2d), LL(0xc6bf9179632ebfbf), LL(0x1c07381b0e3f0707),
    LL(0x8ead012347acadad), LL(0x755aea2fb4b05a5a), LL(0x36836cb51bef8383), LL(0xcc3385ff66b63333),
    LL(0x91633ff2c65c6363), LL(0x0802100a04120202), LL(0x92aa39384993aaaa), LL(0xd971afa8e2de7171),
    LL(0x07c80ecf8dc6c8c8), LL(0x6419c87d32d11919), LL(0x39497270923b4949), LL(0x43d9869aaf5fd9d9),
    LL(0xeff2c31df931f2f2), LL(0xabe34b48dba8e3e3), LL(0x715be22ab6b95b5b), LL(0x1a8834920dbc8888),
    LL(0x529aa4c8293e9a9a), LL(0x98262dbe4c0b2626), LL(0xc8328dfa64bf3232), LL(0xfab0e94a7d59b0b0),
    LL(0x83e91b6acff2e9e9), LL(0x3c0f78331e770f0f), LL(0x73d5e6a6b733d5d5), LL(0x3a8074ba1df48080),
    LL(0xc2be997c6127bebe), LL(0x13cd26de87ebcdcd), LL(0xd034bde468893434), LL(0x3d487a7590324848),
    LL(0xdbffab24e354ffff), LL(0xf57af78ff48d7a7a), LL(0x7a90f4ea3d649090), LL(0x615fc23ebe9d5f5f),
    LL(0x80201da0403d2020), LL(0xbd6867d5d00f6868), LL(0x681ad07234ca1a1a), LL(0x82ae192c41b7aeae),
    LL(0xeab4c95e757db4b4), LL(0x4d549a19a8ce5454), LL(0x7693ece53b7f9393), LL(0x88220daa442f2222),
    LL(0x8d6407e9c8636464), LL(0xe3f1db12ff2af1f1), LL(0xd173bfa2e6cc7373), LL(0x4812905a24821212),
    LL(0x1d403a5d807a4040), LL(0x2008402810480808), LL(0x2bc356e89b95c3c3), LL(0x97ec337bc5dfecec),
    LL(0x4bdb9690ab4ddbdb), LL(0xbea1611f5fc0a1a1), LL(0x0e8d1c8307918d8d), LL(0xf43df5c97ac83d3d),
    LL(0x6697ccf1335b9797), LL(0x0000000000000000), LL(0x1bcf36d483f9cfcf), LL(0xac2b4587566e2b2b),
    LL(0xc57697b3ece17676), LL(0x328264b019e68282), LL(0x7fd6fea9b128d6d6), LL(0x6c1bd87736c31b1b),
    LL(0xeeb5c15b7774b5b5), LL(0x86af112943beafaf), LL(0xb56a77dfd41d6a6a), LL(0x5d50ba0da0ea5050),
    LL(0x0945124c8a574545), LL(0xebf3cb18fb38f3f3), LL(0xc0309df060ad3030), LL(0x9bef2b74c3c4efef),
    LL(0xfc3fe5c37eda3f3f), LL(0x4955921caac75555), LL(0xb2a2791059dba2a2), LL(0x8fea0365c9e9eaea),
    LL(0x89650fecca6a6565), LL(0xd2bab9686903baba), LL(0xbc2f65935e4a2f2f), LL(0x27c04ee79d8ec0c0),
    LL(0x5fdebe81a160dede), LL(0x701ce06c38fc1c1c), LL(0xd3fdbb2ee746fdfd), LL(0x294d52649a1f4d4d),
    LL(0x7292e4e039769292), LL(0xc9758fbceafa7575), LL(0x1806301e0c360606), LL(0x128a249809ae8a8a),
    LL(0xf2b2f940794bb2b2), LL(0xbfe66359d185e6e6), LL(0x380e70361c7e0e0e), LL(0x7c1ff8633ee71f1f),
    LL(0x956237f7c4556262), LL(0x77d4eea3b53ad4d4), LL(0x9aa829324d81a8a8), LL(0x6296c4f431529696),
    LL(0xc3f99b3aef62f9f9), LL(0x33c566f697a3c5c5), LL(0x942535b14a102525), LL(0x7959f220b2ab5959),
    LL(0x2a8454ae15d08484), LL(0xd572b7a7e4c57272), LL(0xe439d5dd72ec3939), LL(0x2d4c5a6198164c4c),
    LL(0x655eca3bbc945e5e), LL(0xfd78e785f09f7878), LL(0xe038ddd870e53838), LL(0x0a8c148605988c8c),
    LL(0x63d1c6b2bf17d1d1), LL(0xaea5410b57e4a5a5), LL(0xafe2434dd9a1e2e2), LL(0x99612ff8c24e6161),
    LL(0xf6b3f1457b42b3b3), LL(0x842115a542342121), LL(0x4a9c94d625089c9c), LL(0x781ef0663cee1e1e),
    LL(0x1143225286614343), LL(0x3bc776fc93b1c7c7), LL(0xd7fcb32be54ffcfc), LL(0x1004201408240404),
    LL(0x5951b208a2e35151), LL(0x5e99bcc72f259999), LL(0xa96d4fc4da226d6d), LL(0x340d68391a650d0d),
    LL(0xcffa8335e979fafa), LL(0x5bdfb684a369dfdf), LL(0xe57ed79bfca97e7e), LL(0x90243db448192424),
    LL(0xec3bc5d776fe3b3b), LL(0x96ab313d4b9aabab), LL(0x1fce3ed181f0cece), LL(0x4411885522991111),
    LL(0x068f0c8903838f8f), LL(0x254e4a6b9c044e4e), LL(0xe6b7d1517366b7b7), LL(0x8beb0b60cbe0ebeb),
    LL(0xf03cfdcc78c13c3c), LL(0x3e817cbf1ffd8181), LL(0x6a94d4fe35409494), LL(0xfbf7eb0cf31cf7f7),
    LL(0xdeb9a1676f18b9b9), LL(0x4c13985f268b1313), LL(0xb02c7d9c58512c2c), LL(0x6bd3d6b8bb05d3d3),
    LL(0xbbe76b5cd38ce7e7), LL(0xa56e57cbdc396e6e), LL(0x37c46ef395aac4c4), LL(0x0c03180f061b0303),
    LL(0x45568a13acdc5656), LL(0x0d441a49885e4444), LL(0xe17fdf9efea07f7f), LL(0x9ea921374f88a9a9),
    LL(0xa82a4d8254672a2a), LL(0xd6bbb16d6b0abbbb), LL(0x23c146e29f87c1c1), LL(0x5153a202a6f15353),
    LL(0x57dcae8ba572dcdc), LL(0x2c0b582716530b0b), LL(0x4e9d9cd327019d9d), LL(0xad6c47c1d82b6c6c),
    LL(0xc43195f562a43131), LL(0xcd7487b9e8f37474), LL(0xfff6e309f115f6f6), LL(0x05460a438c4c4646),
    LL(0x8aac092645a5acac), LL(0x1e893c970fb58989), LL(0x5014a04428b41414), LL(0xa3e15b42dfbae1e1),
    LL(0x5816b04e2ca61616), LL(0xe83acdd274f73a3a), LL(0xb9696fd0d2066969), LL(0x2409482d12410909),
    LL(0xdd70a7ade0d77070), LL(0xe2b6d954716fb6b6), LL(0x67d0ceb7bd1ed0d0), LL(0x93ed3b7ec7d6eded),
    LL(0x17cc2edb85e2cccc), LL(0x15422a5784684242), LL(0x5a98b4c22d2c9898), LL(0xaaa4490e55eda4a4),
    LL(0xa0285d8850752828), LL(0x6d5cda31b8865c5c), LL(0xc7f8933fed6bf8f8), LL(0x228644a411c28686),

    LL(0x186018c07830d818), LL(0x238c2305af462623), LL(0xc63fc67ef991b8c6), LL(0xe887e8136fcdfbe8),
    LL(0x8726874ca113cb87), LL(0xb8dab8a9626d11b8), LL(0x0104010805020901), LL(0x4f214f426e9e0d4f),
    LL(0x36d836adee6c9b36), LL(0xa6a2a6590451ffa6), LL(0xd26fd2debdb90cd2), LL(0xf5f3f5fb06f70ef5),
    LL(0x79f979ef80f29679), LL(0x6fa16f5fcede306f), LL(0x917e91fcef3f6d91), LL(0x525552aa07a4f852),
    LL(0x609d6027fdc04760), LL(0xbccabc89766535bc), LL(0x9b569baccd2b379b), LL(0x8e028e048c018a8e),
    LL(0xa3b6a371155bd2a3), LL(0x0c300c603c186c0c), LL(0x7bf17bff8af6847b), LL(0x35d435b5e16a8035),
    LL(0x1d741de8693af51d), LL(0xe0a7e05347ddb3e0), LL(0xd77bd7f6acb321d7), LL(0xc22fc25eed999cc2),
    LL(0x2eb82e6d965c432e), LL(0x4b314b627a96294b), LL(0xfedffea321e15dfe), LL(0x5741578216aed557),
    LL(0x155415a8412abd15), LL(0x77c1779fb6eee877), LL(0x37dc37a5eb6e9237), LL(0xe5b3e57b56d79ee5),
    LL(0x9f469f8cd923139f), LL(0xf0e7f0d317fd23f0), LL(0x4a354a6a7f94204a), LL(0xda4fda9e95a944da),
    LL(0x587d58fa25b0a258), LL(0xc903c906ca8fcfc9), LL(0x29a429558d527c29), LL(0x0a280a5022145a0a),
    LL(0xb1feb1e14f7f50b1), LL(0xa0baa0691a5dc9a0), LL(0x6bb16b7fdad6146b), LL(0x852e855cab17d985),
    LL(0xbdcebd8173673cbd), LL(0x5d695dd234ba8f5d), LL(0x1040108050209010), LL(0xf4f7f4f303f507f4),
    LL(0xcb0bcb16c08bddcb), LL(0x3ef83eedc67cd33e), LL(0x05140528110a2d05), LL(0x6781671fe6ce7867),
    LL(0xe4b7e47353d597e4), LL(0x279c2725bb4e0227), LL(0x4119413258827341), LL(0x8b168b2c9d0ba78b),
    LL(0xa7a6a7510153f6a7), LL(0x7de97dcf94fab27d), LL(0x956e95dcfb374995), LL(0xd847d88e9fad56d8),
    LL(0xfbcbfb8b30eb70fb), LL(0xee9fee2371c1cdee), LL(0x7ced7cc791f8bb7c), LL(0x66856617e3cc7166),
    LL(0xdd53dda68ea77bdd), LL(0x175c17b84b2eaf17), LL(0x47014702468e4547), LL(0x9e429e84dc211a9e),
    LL(0xca0fca1ec589d4ca), LL(0x2db42d75995a582d), LL(0xbfc6bf9179632ebf), LL(0x071c07381b0e3f07),
    LL(0xad8ead012347acad), LL(0x5a755aea2fb4b05a), LL(0x8336836cb51bef83), LL(0x33cc3385ff66b633),
    LL(0x6391633ff2c65c63), LL(0x020802100a041202), LL(0xaa92aa39384993aa), LL(0x71d971afa8e2de71),
    LL(0xc807c80ecf8dc6c8), LL(0x196419c87d32d119), LL(0x4939497270923b49), LL(0xd943d9869aaf5fd9),
    LL(0xf2eff2c31df931f2), LL(0xe3abe34b48dba8e3), LL(0x5b715be22ab6b95b), LL(0x881a8834920dbc88),
    LL(0x9a529aa4c8293e9a), LL(0x2698262dbe4c0b26), LL(0x32c8328dfa64bf32), LL(0xb0fab0e94a7d59b0),
    LL(0xe983e91b6acff2e9), LL(0x0f3c0f78331e770f), LL(0xd573d5e6a6b733d5), LL(0x803a8074ba1df480),
    LL(0xbec2be997c6127be), LL(0xcd13cd26de87ebcd), LL(0x34d034bde4688934), LL(0x483d487a75903248),
    LL(0xffdbffab24e354ff), LL(0x7af57af78ff48d7a), LL(0x907a90f4ea3d6490), LL(0x5f615fc23ebe9d5f),
    LL(0x2080201da0403d20), LL(0x68bd6867d5d00f68), LL(0x1a681ad07234ca1a), LL(0xae82ae192c41b7ae),
    LL(0xb4eab4c95e757db4), LL(0x544d549a19a8ce54), LL(0x937693ece53b7f93), LL(0x2288220daa442f22),
    LL(0x648d6407e9c86364), LL(0xf1e3f1db12ff2af1), LL(0x73d173bfa2e6cc73), LL(0x124812905a248212),
    LL(0x401d403a5d807a40), LL(0x0820084028104808), LL(0xc32bc356e89b95c3), LL(0xec97ec337bc5dfec),
    LL(0xdb4bdb9690ab4ddb), LL(0xa1bea1611f5fc0a1), LL(0x8d0e8d1c8307918d), LL(0x3df43df5c97ac83d),
    LL(0x976697ccf1335b97), LL(0x0000000000000000), LL(0xcf1bcf36d483f9cf), LL(0x2bac2b4587566e2b),
    LL(0x76c57697b3ece176), LL(0x82328264b019e682), LL(0xd67fd6fea9b128d6), LL(0x1b6c1bd87736c31b),
    LL(0xb5eeb5c15b7774b5), LL(0xaf86af112943beaf), LL(0x6ab56a77dfd41d6a), LL(0x505d50ba0da0ea50),
    LL(0x450945124c8a5745), LL(0xf3ebf3cb18fb38f3), LL(0x30c0309df060ad30), LL(0xef9bef2b74c3c4ef),
    LL(0x3ffc3fe5c37eda3f), LL(0x554955921caac755), LL(0xa2b2a2791059dba2), LL(0xea8fea0365c9e9ea),
    LL(0x6589650fecca6a65), LL(0xbad2bab9686903ba), LL(0x2fbc2f65935e4a2f), LL(0xc027c04ee79d8ec0),
    LL(0xde5fdebe81a160de), LL(0x1c701ce06c38fc1c), LL(0xfdd3fdbb2ee746fd), LL(0x4d294d52649a1f4d),
    LL(0x927292e4e0397692), LL(0x75c9758fbceafa75), LL(0x061806301e0c3606), LL(0x8a128a249809ae8a),
    LL(0xb2f2b2f940794bb2), LL(0xe6bfe66359d185e6), LL(0x0e380e70361c7e0e), LL(0x1f7c1ff8633ee71f),
    LL(0x62956237f7c45562), LL(0xd477d4eea3b53ad4), LL(0xa89aa829324d81a8), LL(0x966296c4f4315296),
    LL(0xf9c3f99b3aef62f9), LL(0xc533c566f697a3c5), LL(0x25942535b14a1025), LL(0x597959f220b2ab59),
    LL(0x842a8454ae15d084), LL(0x72d572b7a7e4c572), LL(0x39e439d5dd72ec39), LL(0x4c2d4c5a6198164c),
    LL(0x5e655eca3bbc945e), LL(0x78fd78e785f09f78), LL(0x38e038ddd870e538), LL(0x8c0a8c148605988c),
    LL(0xd163d1c6b2bf17d1), LL(0xa5aea5410b57e4a5), LL(0xe2afe2434dd9a1e2), LL(0x6199612ff8c24e61),
    LL(0xb3f6b3f1457b42b3), LL(0x21842115a5423421), LL(0x9c4a9c94d625089c), LL(0x1e781ef0663cee1e),
    LL(0x4311432252866143), LL(0xc73bc776fc93b1c7), LL(0xfcd7fcb32be54ffc), LL(0x0410042014082404),
    LL(0x515951b208a2e351), LL(0x995e99bcc72f2599), LL(0x6da96d4fc4da226d), LL(0x0d340d68391a650d),
    LL(0xfacffa8335e979fa), LL(0xdf5bdfb684a369df), LL(0x7ee57ed79bfca97e), LL(0x2490243db4481924),
    LL(0x3bec3bc5d776fe3b), LL(0xab96ab313d4b9aab), LL(0xce1fce3ed181f0ce), LL(0x1144118855229911),
    LL(0x8f068f0c8903838f), LL(0x4e254e4a6b9c044e), LL(0xb7e6b7d1517366b7), LL(0xeb8beb0b60cbe0eb),
    LL(0x3cf03cfdcc78c13c), LL(0x813e817cbf1ffd81), LL(0x946a94d4fe354094), LL(0xf7fbf7eb0cf31cf7),
    LL(0xb9deb9a1676f18b9), LL(0x134c13985f268b13), LL(0x2cb02c7d9c58512c), LL(0xd36bd3d6b8bb05d3),
    LL(0xe7bbe76b5cd38ce7), LL(0x6ea56e57cbdc396e), LL(0xc437c46ef395aac4), LL(0x030c03180f061b03),
    LL(0x5645568a13acdc56), LL(0x440d441a49885e44), LL(0x7fe17fdf9efea07f), LL(0xa99ea921374f88a9),
    LL(0x2aa82a4d8254672a), LL(0xbbd6bbb16d6b0abb), LL(0xc123c146e29f87c1), LL(0x535153a202a6f153),
    LL(0xdc57dcae8ba572dc), LL(0x0b2c0b582716530b), LL(0x9d4e9d9cd327019d), LL(0x6cad6c47c1d82b6c),
    LL(0x31c43195f562a431), LL(0x74cd7487b9e8f374), LL(0xf6fff6e309f115f6), LL(0x4605460a438c4c46),
    LL(0xac8aac092645a5ac), LL(0x891e893c970fb589), LL(0x145014a04428b414), LL(0xe1a3e15b42dfbae1),
    LL(0x165816b04e2ca616), LL(0x3ae83acdd274f73a), LL(0x69b9696fd0d20669), LL(0x092409482d124109),
    LL(0x70dd70a7ade0d770), LL(0xb6e2b6d954716fb6), LL(0xd067d0ceb7bd1ed0), LL(0xed93ed3b7ec7d6ed),
    LL(0xcc17cc2edb85e2cc), LL(0x4215422a57846842), LL(0x985a98b4c22d2c98), LL(0xa4aaa4490e55eda4),
    LL(0x28a0285d88507528), LL(0x5c6d5cda31b8865c), LL(0xf8c7f8933fed6bf8), LL(0x86228644a411c286),

	LL(0x1823c6e887b8014f),
	LL(0x36a6d2f5796f9152),
	LL(0x60bc9b8ea30c7b35),
	LL(0x1de0d7c22e4bfe57),
	LL(0x157737e59ff04ada),
	LL(0x58c9290ab1a06b85),
	LL(0xbd5d10f4cb3e0567),
	LL(0xe427418ba77d95d8),
	LL(0xfbee7c66dd17479e),
	LL(0xca2dbf07ad5a8333)
};


// Whirlpool basic transformation. Transforms state based on block.
#if BYTE_ORDER == LITTLE_ENDIAN
void WhirlpoolTransform(uint64 *digest, const uint64 *block)
{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
#if defined(__GNUC__) && (CRYPTOPP_GCC_VERSION <= 40407)
	/* workaround for gcc 4.4.7 bug under CentOS which causes crash
	 * in inline assembly.
	 * This dummy check that is always false since "block" is aligned. 
	 */
	uint64 lb = (uint64) block;
	if (lb % 16)
	{
		TC_THROW_FATAL_EXCEPTION;
	}
#endif
#endif
	
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	if (HasISSE())
	{
#ifdef __GNUC__
	#if CRYPTOPP_BOOL_X64
		CRYPTOPP_ALIGN_DATA(16) uint64 workspace[16];
	#endif
	__asm__ __volatile__
	(
		INTEL_NOPREFIX
		AS_PUSH_IF86(	bx)
		AS2(	mov		AS_REG_6, WORD_REG(ax))
#else
	#if _MSC_VER < 1300
		AS_PUSH_IF86(	bx)
	#endif
		AS2(	lea		AS_REG_6, [Whirlpool_C])
		AS2(	mov		WORD_REG(cx), digest)
		AS2(	mov		WORD_REG(dx), block)
#endif
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32
		AS2(	mov		eax, esp)
		AS2(	and		esp, -16)
		AS2(	sub		esp, 16*8)
		AS_PUSH_IF86( ax)
     
    #if CRYPTOPP_BOOL_X86
        #define SSE2_workspace	esp+WORD_SZ
    #elif CRYPTOPP_BOOL_X32
        #define SSE2_workspace	esp+(WORD_SZ*2)
    #endif
#else
    #define SSE2_workspace	%3
#endif
		AS2(	xor		esi, esi)
		ASL(0)
		AS2(	movq	mm0, [WORD_REG(cx)+8*WORD_REG(si)])
		AS2(	movq	[SSE2_workspace+8*WORD_REG(si)], mm0)		// k
		AS2(	pxor	mm0, [WORD_REG(dx)+8*WORD_REG(si)])
		AS2(	movq	[SSE2_workspace+64+8*WORD_REG(si)], mm0)	// s
		AS2(	movq	[WORD_REG(cx)+8*WORD_REG(si)], mm0)
		AS1(	inc		WORD_REG(si))
		AS2(	cmp		WORD_REG(si), 8)
		ASJ(	jne,	0, b)

		AS2(	xor		esi, esi)
		ASL(1)

#define KSL0(a, b)	AS2(movq	mm##a, b)
#define KSL1(a, b)	AS2(pxor	mm##a, b)

#define KSL(op, i, a, b, c, d)	\
	AS2(mov		eax, [SSE2_workspace+8*i])\
	AS2(movzx	edi, al)\
	KSL##op(a, [AS_REG_6+3*2048+8*WORD_REG(di)])\
	AS2(movzx	edi, ah)\
	KSL##op(b, [AS_REG_6+2*2048+8*WORD_REG(di)])\
	AS2(shr		eax, 16)\
	AS2(movzx	edi, al)\
	AS2(shr		eax, 8)\
	KSL##op(c, [AS_REG_6+1*2048+8*WORD_REG(di)])\
	KSL##op(d, [AS_REG_6+0*2048+8*WORD_REG(ax)])

#define KSH0(a, b)	\
	ASS(pshufw	mm##a, mm##a, 1, 0, 3, 2)\
	AS2(pxor	mm##a, b)
#define KSH1(a, b)	\
	AS2(pxor	mm##a, b)
#define KSH2(a, b)	\
	AS2(pxor	mm##a, b)\
	AS2(movq	[SSE2_workspace+8*a], mm##a)

#define KSH(op, i, a, b, c, d)	\
	AS2(mov		eax, [SSE2_workspace+8*((i+4)-8*((i+4)/8))+4])\
	AS2(movzx	edi, al)\
	KSH##op(a, [AS_REG_6+3*2048+8*WORD_REG(di)])\
	AS2(movzx	edi, ah)\
	KSH##op(b, [AS_REG_6+2*2048+8*WORD_REG(di)])\
	AS2(shr		eax, 16)\
	AS2(movzx	edi, al)\
	AS2(shr		eax, 8)\
	KSH##op(c, [AS_REG_6+1*2048+8*WORD_REG(di)])\
	KSH##op(d, [AS_REG_6+0*2048+8*WORD_REG(ax)])

#define TSL(op, i, a, b, c, d)	\
	AS2(mov		eax, [SSE2_workspace+64+8*i])\
	AS2(movzx	edi, al)\
	KSL##op(a, [AS_REG_6+3*2048+8*WORD_REG(di)])\
	AS2(movzx	edi, ah)\
	KSL##op(b, [AS_REG_6+2*2048+8*WORD_REG(di)])\
	AS2(shr		eax, 16)\
	AS2(movzx	edi, al)\
	AS2(shr		eax, 8)\
	KSL##op(c, [AS_REG_6+1*2048+8*WORD_REG(di)])\
	KSL##op(d, [AS_REG_6+0*2048+8*WORD_REG(ax)])

#define TSH0(a, b)	\
	ASS(pshufw	mm##a, mm##a, 1, 0, 3, 2)\
	AS2(pxor	mm##a, [SSE2_workspace+8*a])\
	AS2(pxor	mm##a, b)
#define TSH1(a, b)	\
	AS2(pxor	mm##a, b)
#define TSH2(a, b)	\
	AS2(pxor	mm##a, b)\
	AS2(movq	[SSE2_workspace+64+8*a], mm##a)
#define TSH3(a, b)	\
	AS2(pxor	mm##a, b)\
	AS2(pxor	mm##a, [WORD_REG(cx)+8*a])\
	AS2(movq	[WORD_REG(cx)+8*a], mm##a)

#define TSH(op, i, a, b, c, d)	\
	AS2(mov		eax, [SSE2_workspace+64+8*((i+4)-8*((i+4)/8))+4])\
	AS2(movzx	edi, al)\
	TSH##op(a, [AS_REG_6+3*2048+8*WORD_REG(di)])\
	AS2(movzx	edi, ah)\
	TSH##op(b, [AS_REG_6+2*2048+8*WORD_REG(di)])\
	AS2(shr		eax, 16)\
	AS2(movzx	edi, al)\
	AS2(shr		eax, 8)\
	TSH##op(c, [AS_REG_6+1*2048+8*WORD_REG(di)])\
	TSH##op(d, [AS_REG_6+0*2048+8*WORD_REG(ax)])

		KSL(0, 4, 3, 2, 1, 0)
		KSL(0, 0, 7, 6, 5, 4)
		KSL(1, 1, 0, 7, 6, 5)
		KSL(1, 2, 1, 0, 7, 6)
		KSL(1, 3, 2, 1, 0, 7)
		KSL(1, 5, 4, 3, 2, 1)
		KSL(1, 6, 5, 4, 3, 2)
		KSL(1, 7, 6, 5, 4, 3)
		KSH(0, 0, 7, 6, 5, 4)
		KSH(0, 4, 3, 2, 1, 0)
		KSH(1, 1, 0, 7, 6, 5)
		KSH(1, 2, 1, 0, 7, 6)
		KSH(1, 5, 4, 3, 2, 1)
		KSH(1, 6, 5, 4, 3, 2)
		KSH(2, 3, 2, 1, 0, 7)
		KSH(2, 7, 6, 5, 4, 3)

		AS2(	pxor	mm0, [AS_REG_6 + 16*1024 + WORD_REG(si)*8])
		AS2(	movq	[SSE2_workspace], mm0)

		TSL(0, 4, 3, 2, 1, 0)
		TSL(0, 0, 7, 6, 5, 4)
		TSL(1, 1, 0, 7, 6, 5)
		TSL(1, 2, 1, 0, 7, 6)
		TSL(1, 3, 2, 1, 0, 7)
		TSL(1, 5, 4, 3, 2, 1)
		TSL(1, 6, 5, 4, 3, 2)
		TSL(1, 7, 6, 5, 4, 3)
		TSH(0, 0, 7, 6, 5, 4)
		TSH(0, 4, 3, 2, 1, 0)
		TSH(1, 1, 0, 7, 6, 5)
		TSH(1, 2, 1, 0, 7, 6)
		TSH(1, 5, 4, 3, 2, 1)
		TSH(1, 6, 5, 4, 3, 2)

		AS1(	inc		WORD_REG(si))
		AS2(	cmp		WORD_REG(si), 10)
		ASJ(	je,		2, f)

		TSH(2, 3, 2, 1, 0, 7)
		TSH(2, 7, 6, 5, 4, 3)

		ASJ(	jmp,	1, b)
		ASL(2)

		TSH(3, 3, 2, 1, 0, 7)
		TSH(3, 7, 6, 5, 4, 3)

#undef KSL
#undef KSH
#undef TSL
#undef TSH

		AS_POP_IF86(	sp)
		AS1(	emms)

#if defined(__GNUC__) || (defined(_MSC_VER) && _MSC_VER < 1300)
		AS_POP_IF86(	bx)
#endif
#ifdef __GNUC__
		ATT_PREFIX
			:
			: "a" (Whirlpool_C), "c" (digest), "d" (block)
	#if CRYPTOPP_BOOL_X64
			, "r" (workspace)
	#endif
			: "%esi", "%edi", "memory", "cc"
	#if CRYPTOPP_BOOL_X64
			, "%r9"
	#endif
		);
#endif
	}
	else
#endif		// #ifdef CRYPTOPP_X86_ASM_AVAILABLE
	{
		union { unsigned char ch[64]; unsigned long long ll[8]; } K, state;
		unsigned long long L[8];
		int r, i;

		i = 0; do state.ll[i] = (K.ll[i] = digest[i]) ^ (block)[i]; while (++i < 8);

		r = 0; do {
			L[0] = Whirlpool_C[0*256 + K.ch[0 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[7 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[6 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[5 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[4 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[3 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[2 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[1 * 8 + 0]] ^ Whirlpool_C[2048 + r];
			L[1] = Whirlpool_C[0*256 + K.ch[1 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[0 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[7 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[6 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[5 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[4 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[3 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[2 * 8 + 0]];
			L[2] = Whirlpool_C[0*256 + K.ch[2 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[1 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[0 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[7 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[6 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[5 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[4 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[3 * 8 + 0]];
			L[3] = Whirlpool_C[0*256 + K.ch[3 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[2 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[1 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[0 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[7 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[6 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[5 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[4 * 8 + 0]];
			L[4] = Whirlpool_C[0*256 + K.ch[4 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[3 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[2 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[1 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[0 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[7 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[6 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[5 * 8 + 0]];
			L[5] = Whirlpool_C[0*256 + K.ch[5 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[4 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[3 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[2 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[1 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[0 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[7 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[6 * 8 + 0]];
			L[6] = Whirlpool_C[0*256 + K.ch[6 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[5 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[4 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[3 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[2 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[1 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[0 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[7 * 8 + 0]];
			L[7] = Whirlpool_C[0*256 + K.ch[7 * 8 + 7]] ^ Whirlpool_C[1*256 + K.ch[6 * 8 + 6]] ^ Whirlpool_C[2*256 + K.ch[5 * 8 + 5]] ^ Whirlpool_C[3*256 + K.ch[4 * 8 + 4]] ^ Whirlpool_C[4*256 + K.ch[3 * 8 + 3]] ^ Whirlpool_C[5*256 + K.ch[2 * 8 + 2]] ^ Whirlpool_C[6*256 + K.ch[1 * 8 + 1]] ^ Whirlpool_C[7*256 + K.ch[0 * 8 + 0]];

			L[0] = (K.ll[0] = L[0]) ^ Whirlpool_C[0*256 + state.ch[0 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[7 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[6 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[5 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[4 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[3 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[2 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[1 * 8 + 0]];
			L[1] = (K.ll[1] = L[1]) ^ Whirlpool_C[0*256 + state.ch[1 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[0 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[7 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[6 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[5 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[4 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[3 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[2 * 8 + 0]];
			L[2] = (K.ll[2] = L[2]) ^ Whirlpool_C[0*256 + state.ch[2 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[1 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[0 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[7 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[6 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[5 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[4 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[3 * 8 + 0]];
			L[3] = (K.ll[3] = L[3]) ^ Whirlpool_C[0*256 + state.ch[3 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[2 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[1 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[0 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[7 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[6 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[5 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[4 * 8 + 0]];
			L[4] = (K.ll[4] = L[4]) ^ Whirlpool_C[0*256 + state.ch[4 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[3 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[2 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[1 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[0 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[7 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[6 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[5 * 8 + 0]];
			L[5] = (K.ll[5] = L[5]) ^ Whirlpool_C[0*256 + state.ch[5 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[4 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[3 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[2 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[1 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[0 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[7 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[6 * 8 + 0]];
			L[6] = (K.ll[6] = L[6]) ^ Whirlpool_C[0*256 + state.ch[6 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[5 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[4 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[3 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[2 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[1 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[0 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[7 * 8 + 0]];
			L[7] = (K.ll[7] = L[7]) ^ Whirlpool_C[0*256 + state.ch[7 * 8 + 7]] ^ Whirlpool_C[1*256 + state.ch[6 * 8 + 6]] ^ Whirlpool_C[2*256 + state.ch[5 * 8 + 5]] ^ Whirlpool_C[3*256 + state.ch[4 * 8 + 4]] ^ Whirlpool_C[4*256 + state.ch[3 * 8 + 3]] ^ Whirlpool_C[5*256 + state.ch[2 * 8 + 2]] ^ Whirlpool_C[6*256 + state.ch[1 * 8 + 1]] ^ Whirlpool_C[7*256 + state.ch[0 * 8 + 0]];

			memcpy(state.ll, L, sizeof(L));
		} while (++r < 10);

		i = 0; do digest[i] ^= L[i] ^ (block)[i]; while (++i < 8);
	}
}
#else
void WhirlpoolTransform(uint64 *digest, const uint64 *block)
{
	union { unsigned char ch[64]; unsigned long long ll[8]; } K, state;
	unsigned long long L[8];
	int r, i;

	i = 0;
	do {
		state.ll[i] = (K.ll[i] = digest[i]) ^ block[i];
	} while (++i < 8);

	r = 0;
	do {
		L[0] = Whirlpool_C[0*256 + K.ch[0 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[7 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[6 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[5 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[4 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[3 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[2 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[1 * 8 + 7]] ^
		       Whirlpool_C[2048 + r];

		L[1] = Whirlpool_C[0*256 + K.ch[1 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[0 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[7 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[6 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[5 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[4 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[3 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[2 * 8 + 7]];

		L[2] = Whirlpool_C[0*256 + K.ch[2 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[1 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[0 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[7 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[6 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[5 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[4 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[3 * 8 + 7]];

		L[3] = Whirlpool_C[0*256 + K.ch[3 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[2 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[1 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[0 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[7 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[6 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[5 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[4 * 8 + 7]];

		L[4] = Whirlpool_C[0*256 + K.ch[4 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[3 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[2 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[1 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[0 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[7 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[6 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[5 * 8 + 7]];

		L[5] = Whirlpool_C[0*256 + K.ch[5 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[4 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[3 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[2 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[1 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[0 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[7 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[6 * 8 + 7]];

		L[6] = Whirlpool_C[0*256 + K.ch[6 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[5 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[4 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[3 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[2 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[1 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[0 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[7 * 8 + 7]];

		L[7] = Whirlpool_C[0*256 + K.ch[7 * 8 + 0]] ^ Whirlpool_C[1*256 + K.ch[6 * 8 + 1]] ^
		       Whirlpool_C[2*256 + K.ch[5 * 8 + 2]] ^ Whirlpool_C[3*256 + K.ch[4 * 8 + 3]] ^
		       Whirlpool_C[4*256 + K.ch[3 * 8 + 4]] ^ Whirlpool_C[5*256 + K.ch[2 * 8 + 5]] ^
		       Whirlpool_C[6*256 + K.ch[1 * 8 + 6]] ^ Whirlpool_C[7*256 + K.ch[0 * 8 + 7]];

		// Round key mixing and substitution (with big-endian adjustment)
		for (i = 0; i < 8; ++i) {
			K.ll[i] = L[i];
			L[i] ^= Whirlpool_C[0*256 + state.ch[i * 8 + 0]] ^ Whirlpool_C[1*256 + state.ch[((i - 1 + 8) % 8) * 8 + 1]] ^
			         Whirlpool_C[2*256 + state.ch[((i - 2 + 8) % 8) * 8 + 2]] ^ Whirlpool_C[3*256 + state.ch[((i - 3 + 8) % 8) * 8 + 3]] ^
			         Whirlpool_C[4*256 + state.ch[((i - 4 + 8) % 8) * 8 + 4]] ^ Whirlpool_C[5*256 + state.ch[((i - 5 + 8) % 8) * 8 + 5]] ^
			         Whirlpool_C[6*256 + state.ch[((i - 6 + 8) % 8) * 8 + 6]] ^ Whirlpool_C[7*256 + state.ch[((i - 7 + 8) % 8) * 8 + 7]];
		}

		memcpy(state.ll, L, sizeof(L));
	} while (++r < 10);

	i = 0;
	do {
		digest[i] ^= L[i] ^ block[i];
	} while (++i < 8);
}
#endif

static uint64 HashMultipleBlocks(WHIRLPOOL_CTX * const ctx, const uint64 *input, uint64 length)
{
	uint64* dataBuf = ctx->data;
	do
	{
#if BYTE_ORDER == BIG_ENDIAN
		WhirlpoolTransform(ctx->state, input);
#else
		CorrectEndianness(dataBuf, input, 64);
		WhirlpoolTransform(ctx->state, dataBuf);
#endif
		input += 8;
		length -= 64;
	}
	while (length >= 64);
	return length;
}

/**
 * Initialize the hashing state.
 */
void WHIRLPOOL_init(WHIRLPOOL_CTX * const ctx) {
	 ctx->countHi = 0;
	 ctx->countLo = 0;
	 memset (ctx->data, 0, 8 * sizeof (uint64));
	 memset (ctx->state, 0, 8 * sizeof (uint64));
}

/**
 * Delivers input data to the hashing algorithm.
 *
 * @param    source        plaintext data to hash.
 * @param    sourceBits    how many bits of plaintext to process.
 *
 * This method maintains the invariant: bufferBits < DIGESTBITS
 */
void WHIRLPOOL_add(const unsigned char * input,
               unsigned __int32 sourceBytes,
               WHIRLPOOL_CTX * const ctx) 
{
	uint64 num, oldCountLo = ctx->countLo, oldCountHi = ctx->countHi;
	uint64 len = sourceBytes;
	if ((ctx->countLo = oldCountLo + (uint64)len) < oldCountLo)
		ctx->countHi++;             // carry from low to high

	if (ctx->countHi < oldCountHi)
		return;
	else
	{
		uint64* dataBuf = ctx->data;
		uint8* data = (uint8 *)dataBuf;		
		num = oldCountLo & 63;

		if (num != 0)	// process left over data
		{
			if (num+len >= 64)
			{
				memcpy(data+num, input, (size_t) (64-num));
				HashMultipleBlocks(ctx, dataBuf, 64);
				input += (64-num);
				len -= (64-num);
				// drop through and do the rest
			}
			else
			{
				memcpy(data+num, input, (size_t) len);
				return;
			}
		}

		// now process the input data in blocks of 64 bytes and save the leftovers to ctx->data
        if (len >= 64)
        {
            if (input == data)
            {
                HashMultipleBlocks(ctx, dataBuf, 64);
                return;
            }
            else
            {
#ifndef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
                if (IsAligned16(input))
#endif
                {
                    uint64 leftOver = HashMultipleBlocks(ctx, (uint64*)input, len);
                    input += (len - leftOver);
                    len = leftOver;
                }
#ifndef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
                else
                    do
                    {   // copy input first if it's not aligned correctly
                        memcpy(data, input, 64);
                        HashMultipleBlocks(ctx, dataBuf, 64);
                        input += 64;
                        len -= 64;
                    } while (len >= 64);
#endif
            }
        }

		if (len && data != input)
			memcpy(data, input, (size_t) len);
	}
}

/**
 * Get the hash value from the hashing state.
 * 
 * This method uses the invariant: bufferBits < DIGESTBITS
 */
void WHIRLPOOL_finalize(WHIRLPOOL_CTX * const ctx,
                    unsigned char * result) 
{
	unsigned int num = ctx->countLo & 63;
	uint64* dataBuf = ctx->data;
	uint64* stateBuf = ctx->state;
	uint8* data = (uint8 *)dataBuf;

	data[num++] = 0x80;
	if (num <= 32)
		memset(data+num, 0, 32-num);
	else
	{
		memset(data+num, 0, 64-num);
		HashMultipleBlocks(ctx, dataBuf, 64);
		memset(data, 0, 32);
	}
#if BYTE_ORDER == LITTLE_ENDIAN
	CorrectEndianness(dataBuf, dataBuf, 32);
#endif

	dataBuf[4] = 0;
	dataBuf[5] = 0;
	dataBuf[6] = (ctx->countLo >> (8*sizeof(uint64)-3)) + (ctx->countHi << 3);
	dataBuf[7] = ctx->countLo << 3;

	WhirlpoolTransform(stateBuf, dataBuf);
#if BYTE_ORDER == LITTLE_ENDIAN
	CorrectEndianness(stateBuf, stateBuf, 64);
#endif
	memcpy(result, stateBuf, 64);
}
