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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "Common/Endian.h"
#include "cpu.h"
#include "misc.h"

#include "Whirlpool.h"

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
CRYPTOPP_ALIGN_DATA(16) static const uint64 Whirlpool_C[4*256+R] CRYPTOPP_SECTION_ALIGN16 = {
#else
static const uint64 Whirlpool_C[4*256+R] = {
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
void WhirlpoolTransform(uint64 *digest, const uint64 *block)
{
#if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
	if (HasISSE())
	{
		// MMX version has the same structure as C version below
#ifdef __GNUC__
	#if CRYPTOPP_BOOL_X64
		uint64 workspace[16];
	#endif
	__asm__ __volatile__
	(
		".intel_syntax noprefix;"
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
#if CRYPTOPP_BOOL_X86
		AS2(	mov		eax, esp)
		AS2(	and		esp, -16)
		AS2(	sub		esp, 16*8)
		AS1(	push	eax)
	#define SSE2_workspace	esp+WORD_SZ
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

		AS2(	pxor	mm0, [AS_REG_6 + 8*1024 + WORD_REG(si)*8])
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
		".att_syntax prefix;"
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
	uint64 s[8];	// the cipher state
	uint64 k[8];	// the round key
	int r;
	uint64 w0 = 0, w1 = 0, w2 = 0, w3 = 0, w4 = 0, w5 = 0, w6 = 0, w7 = 0;	// temporary storage

	// Compute and apply K^0 to the cipher state
	// Also apply part of the Miyaguchi-Preneel compression function
	for (r=0; r<8; r++)
		digest[r] = s[r] = block[r] ^ (k[r] = digest[r]);

#define KSL(op, i, a, b, c, d)	\
	t = (uint32)k[i];\
	w##a = Whirlpool_C[3*256 + (byte)t] ^ (op ? w##a : 0);\
	t >>= 8;\
	w##b = Whirlpool_C[2*256 + (byte)t] ^ (op ? w##b : 0);\
	t >>= 8;\
	w##c = Whirlpool_C[1*256 + (byte)t] ^ (op ? w##c : 0);\
	t >>= 8;\
	w##d = Whirlpool_C[0*256 + t]       ^ (op ? w##d : 0);

#define KSH(op, i, a, b, c, d)	\
	t = (uint32)(k[(i+4)%8]>>32);\
	w##a = Whirlpool_C[3*256 + (byte)t] ^ (op ? w##a : rotr64(w##a, 32));\
	if (op==2) k[a] = w##a;\
	t >>= 8;\
	w##b = Whirlpool_C[2*256 + (byte)t] ^ (op ? w##b : rotr64(w##b, 32));\
	if (op==2) k[b] = w##b;\
	t >>= 8;\
	w##c = Whirlpool_C[1*256 + (byte)t] ^ (op ? w##c : rotr64(w##c, 32));\
	if (op==2) k[c] = w##c;\
	t >>= 8;\
	w##d = Whirlpool_C[0*256 + t]       ^ (op ? w##d : rotr64(w##d, 32));\
	if (op==2) k[d] = w##d;\

#define TSL(op, i, a, b, c, d)	\
	t = (uint32)s[i];\
	w##a = Whirlpool_C[3*256 + (byte)t] ^ (op ? w##a : 0);\
	t >>= 8;\
	w##b = Whirlpool_C[2*256 + (byte)t] ^ (op ? w##b : 0);\
	t >>= 8;\
	w##c = Whirlpool_C[1*256 + (byte)t] ^ (op ? w##c : 0);\
	t >>= 8;\
	w##d = Whirlpool_C[0*256 + t]       ^ (op ? w##d : 0);

#define TSH_OP(op, a, b)	\
	w##a = Whirlpool_C[b*256 + (byte)t] ^ (op ? w##a : rotr64(w##a, 32) ^ k[a]);\
	if (op==2) s[a] = w##a;\
	if (op==3) digest[a] ^= w##a;\

#define TSH(op, i, a, b, c, d)	\
	t = (uint32)(s[(i+4)%8]>>32);\
	TSH_OP(op, a, 3);\
	t >>= 8;\
	TSH_OP(op, b, 2);\
	t >>= 8;\
	TSH_OP(op, c, 1);\
	t >>= 8;\
	TSH_OP(op, d, 0);\

	// Iterate over all rounds:
	r=0;
	while (1)
	{
		uint32 t;

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

		k[0] ^= Whirlpool_C[1024+r];

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

		if (++r < R)
		{
			TSH(2, 3, 2, 1, 0, 7)
			TSH(2, 7, 6, 5, 4, 3)
		}
		else
		{
			TSH(3, 3, 2, 1, 0, 7)
			TSH(3, 7, 6, 5, 4, 3)
			break;
		}
	}
	}
}

static uint64 HashMultipleBlocks(WHIRLPOOL_CTX * const ctx, const uint64 *input, uint64 length)
{
	uint64* dataBuf = ctx->data;
	do
	{
#if BYTE_ORDER == BIG_ENDIAN
		WhirlpoolTransform(ctx->state, input);
#else
		CorrectEndianess(dataBuf, input, 64);
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
               unsigned __int32 sourceBits,
               WHIRLPOOL_CTX * const ctx) 
{
	uint64 num, oldCountLo = ctx->countLo, oldCountHi = ctx->countHi;
	uint64 len = sourceBits >> 3;
	if ((ctx->countLo = oldCountLo + (uint64)len) < oldCountLo)
		ctx->countHi++;             // carry from low to high

	if (ctx->countHi < oldCountHi)
		return;
	else
	{
		uint64* dataBuf = ctx->data;
		byte* data = (byte *)dataBuf;		
		num = oldCountLo & 63;

		if (num != 0)	// process left over data
		{
			if (num+len >= 64)
			{
				memcpy(data+num, input, (size_t) (64-num));
				HashMultipleBlocks(ctx, dataBuf, 64);
				input += (64-num);
				len -= (64-num);
				num = 0;
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
			else if (IsAligned16(input))
			{
				uint64 leftOver = HashMultipleBlocks(ctx, (uint64 *)input, len);
				input += (len - leftOver);
				len = leftOver;
			}
			else
				do
				{   // copy input first if it's not aligned correctly
					memcpy(data, input, 64);
					HashMultipleBlocks(ctx, dataBuf, 64);
					input+=64;
					len-=64;
				} while (len >= 64);
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
	byte* data = (byte *)dataBuf;

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
	CorrectEndianess(dataBuf, dataBuf, 32);
#endif

	dataBuf[4] = 0;
	dataBuf[5] = 0;
	dataBuf[6] = (ctx->countLo >> (8*sizeof(uint64)-3)) + (ctx->countHi << 3);
	dataBuf[7] = ctx->countLo << 3;

	WhirlpoolTransform(stateBuf, dataBuf);
#if BYTE_ORDER == LITTLE_ENDIAN
	CorrectEndianess(stateBuf, stateBuf, 64);
#endif
	memcpy(result, stateBuf, 64);
}
