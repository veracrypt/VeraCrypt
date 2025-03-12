#
# Derived from source code of TrueCrypt 7.1a, which is
# Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
# by the TrueCrypt License 3.0.
#
# Modifications and additions to the original source code (contained in this file)
# and all other portions of this file are Copyright (c) 2013-2017 IDRIX
# and are governed by the Apache License 2.0 the full text of which is
# contained in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

PATH=$PATH:/usr/bin:/bin:/usr/sbin:/sbin:/usr/bin/X11

PACKAGE_DIR=$(dirname $(mktemp))
PACKAGE=$PACKAGE_DIR/$PACKAGE_NAME
umask 022


# Terminal setup

TTY=0
tty >/dev/null 2>/dev/null && TTY=1

GUI=0
XMESSAGE=0
XTERM=0
GTERM=0
KTERM=0


case $PACKAGE_TYPE in
	tar)
		PACKAGE_INSTALLER=tar
		if tar --help | grep -q -- '--keep-directory-symlink'; then
			PACKAGE_INSTALLER_OPTS='-C / --keep-directory-symlink --no-overwrite-dir -xpzvf'
		else
			PACKAGE_INSTALLER_OPTS='-C / --no-overwrite-dir -xpzvf'
		fi
		;;
esac


if [ -n "$DISPLAY" -a "$INSTALLER_TYPE" != "console" ]
then
	GUI=1
	which xmessage >/dev/null 2>/dev/null && XMESSAGE=1
	which xterm >/dev/null 2>/dev/null && XTERM=1
	which gnome-terminal >/dev/null 2>/dev/null && GTERM=1
	which konsole >/dev/null 2>/dev/null && KTERM=1
fi

if [ $TTY -eq 0 ]
then
	[ $GUI -eq 0 ] && echo 'Error: Terminal required' >&2 && exit 1

	if [ $XMESSAGE -eq 0 ] || ([ $XTERM -eq 0 ] && [ $GTERM -eq 0 ] && [ $KTERM -eq 0 ])
	then
		which gnome-terminal && exec gnome-terminal -- "$0"
		which konsole && exec konsole -e "$0"
		which xterm && exec xterm -e "$0"

		[ $XMESSAGE -eq 1 ] && show_exit_message 'Error: Terminal required'
		exit 1
	fi
fi

if [ $XMESSAGE -eq 0 ] || ([ $XTERM -eq 0 ] && [ $GTERM -eq 0 ] && [ $KTERM -eq 0 ])
then
	GUI=0
	XMESSAGE=0
	XTERM=0
	GTERM=0
	KTERM=0
fi


show_message()
{
	if [ $GUI -eq 1 ]
	then
		if [ $XMESSAGE -eq 1 ]
		then
			xmessage -title "VeraCrypt Setup" -center -buttons OK -default OK "$*"
		else
			if [ $TTY -eq 1 ]
			then
				echo "$*"
			else
				if [ $XTERM -eq 1 ]
				then
					xterm -T 'VeraCrypt Setup' -e sh -c "echo $*; read A"
				else
					if [ $GTERM -eq 1 ]
					then
						gnome-terminal --title='VeraCrypt Setup' -- sh -c "echo $*; read A"
					else
						if [ $KTERM -eq 1 ]
						then
							konsole --qwindowtitle 'VeraCrypt Setup' -e sh -c "echo $*; read A"
						fi
					fi
				fi
			fi
		fi
	else
		echo "$*"
	fi
}

show_exit_message()
{
	show_message "$*"

	if [ $XMESSAGE -eq 0 ]
	then
		printf 'Press Enter to exit... '
		read A
	fi
}

# License extraction

trap 'rm -f $LICENSE $PACKAGE; exit 1' HUP INT QUIT TERM
LICENSE=$(mktemp)

cat >$LICENSE <<_LICENSE_END
VeraCrypt License
Software distributed under this license is distributed on an "AS
IS" BASIS WITHOUT WARRANTIES OF ANY KIND. THE AUTHORS AND
DISTRIBUTORS OF THE SOFTWARE DISCLAIM ANY LIABILITY. ANYONE WHO
USES, COPIES, MODIFIES, OR (RE)DISTRIBUTES ANY PART OF THE
SOFTWARE IS, BY SUCH ACTION(S), ACCEPTING AND AGREEING TO BE
BOUND BY ALL TERMS AND CONDITIONS OF THIS LICENSE. IF YOU DO NOT
ACCEPT THEM, DO NOT USE, COPY, MODIFY, NOR (RE)DISTRIBUTE THE
SOFTWARE, NOR ANY PART(S) THEREOF.

VeraCrypt is multi-licensed under Apache License 2.0 and
the TrueCrypt License version 3.0, a verbatim copy of both
licenses can be found below.

This license does not grant you rights to use any
contributors' name, logo, or trademarks, including IDRIX,
VeraCrypt and all derivative names.
For example, the following names are not allowed: VeraCrypt,
VeraCrypt+, VeraCrypt Professional, iVeraCrypt, etc. Nor any
other names confusingly similar to the name VeraCrypt (e.g.,
Vera-Crypt, Vera Crypt, VerKrypt, etc.)
____________________________________________________________

Apache License
Version 2.0, January 2004
https://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use,
reproduction, and distribution as defined by Sections 1 through
9 of this document.

"Licensor" shall mean the copyright owner or entity authorized
by the copyright owner that is granting the License.

"Legal Entity" shall mean the union of the acting entity and all
other entities that control, are controlled by, or are under
common control with that entity. For the purposes of this
definition, "control" means (i) the power, direct or indirect,
to cause the direction or management of such entity, whether by
contract or otherwise, or (ii) ownership of fifty percent (50%)
or more of the outstanding shares, or (iii) beneficial ownership
of such entity.

"You" (or "Your") shall mean an individual or Legal Entity
exercising permissions granted by this License.

"Source" form shall mean the preferred form for making
modifications, including but not limited to software source
code, documentation source, and configuration files.

"Object" form shall mean any form resulting from mechanical
transformation or translation of a Source form, including but
not limited to compiled object code, generated documentation,
and conversions to other media types.

"Work" shall mean the work of authorship, whether in Source or
Object form, made available under the License, as indicated by
a copyright notice that is included in or attached to the work
(an example is provided in the Appendix below).

"Derivative Works" shall mean any work, whether in Source or
Object form, that is based on (or derived from) the Work and
for which the editorial revisions, annotations, elaborations, or
other modifications represent, as a whole, an original work of
authorship. For the purposes of this License, Derivative Works
shall not include works that remain separable from, or merely
link (or bind by name) to the interfaces of, the Work and
Derivative Works thereof.

"Contribution" shall mean any work of authorship, including
the original version of the Work and any modifications or
additions to that Work or Derivative Works thereof, that is
intentionally submitted to Licensor for inclusion in the Work by
the copyright owner or by an individual or Legal Entity
authorized to submit on behalf of the copyright owner. For the
purposes of this definition, "submitted" means any form
of electronic, verbal, or written communication sent to the
Licensor or its representatives, including but not limited to
communication on electronic mailing lists, source code control
systems, and issue tracking systems that are managed by, or on
behalf of, the Licensor for the purpose of discussing and
improving the Work, but excluding communication that is
conspicuously marked or otherwise designated in writing by the
copyright owner as "Not a Contribution."

"Contributor" shall mean Licensor and any individual or Legal
Entity on behalf of whom a Contribution has been received by
Licensor and subsequently incorporated within the Work.

2. Grant of Copyright License. Subject to the terms and
conditions of this License, each Contributor hereby grants to
You a perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable copyright license to reproduce,
prepare Derivative Works of, publicly display, publicly perform,
sublicense, and distribute the Work and such Derivative Works
in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions
of this License, each Contributor hereby grants to You a
perpetual, worldwide, non-exclusive, no-charge, royalty-free,
irrevocable(except as stated in this section) patent license
to make, have made, use, offer to sell, sell, import, and
otherwise transfer the Work, where such license applies only
to those patent claims licensable by such Contributor that are
necessarily infringed by their Contribution(s) alone or by
combination of their Contribution(s) with the Work to which such
Contribution(s) was submitted. If You institute patent
litigation against any entity (including a cross-claim or
counterclaim in a lawsuit) alleging that the Work or a
Contribution incorporated within the Work constitutes direct or
contributory patent infringement, then any patent licenses
granted to You under this License for that Work shall terminate
as of the date such litigation is filed.

4. Redistribution. You may reproduce and distribute copies of
the Work or Derivative Works thereof in any medium, with or
without modifications, and in Source or Object form, provided
that You meet the following conditions:

(a) You must give any other recipients of the Work or Derivative
    Works a copy of this License; and
(b) You must cause any modified files to carry prominent notices
    stating that You changed the files; and
(c) You must retain, in the Source form of any Derivative Works
    that You distribute, all copyright, patent, trademark, and
    attribution notices from the Source form of the Work,
    excluding those notices that do not pertain to any part of
    the Derivative Works; and
(d) If the Work includes a "NOTICE" text file as part of its
    distribution, then any Derivative Works that You distribute
    must include a readable copy of the attribution notices
    contained within such NOTICE file, excluding those notices
    that do not pertain to any part of the Derivative Works, in
    at least one of the following places: within a NOTICE text
    file distributed as part of the Derivative Works; within the
    Source form or documentation, if provided along with the
    Derivative Works; or, within a display generated by the
    Derivative Works, if and wherever such third-party notices
    normally appear. The contents of the NOTICE file are for
    informational purposes only and do not modify the License.
    You may add Your own attribution notices within Derivative
    Works that You distribute, alongside or as an addendum to
    the NOTICE text from the Work, provided that such additional
    attribution notices cannot be construed as modifying
    the License.

You may add Your own copyright statement to Your modifications
and may provide additional or different license terms
and conditions for use, reproduction, or distribution of
Your modifications, or for any such Derivative Works as a whole,
provided Your use, reproduction, and distribution of the Work
otherwise complies with the conditions stated in this License.

5. Submission of Contributions. Unless You explicitly state
otherwise, any Contribution intentionally submitted for
inclusion in the Work by You to the Licensor shall be under the
terms and conditions of this License, without any additional
terms or conditions. Notwithstanding the above, nothing herein
shall supersede or modify the terms of any separate license
agreement you may have executed with Licensor regarding such
Contributions.

6. Trademarks. This License does not grant permission to use the
trade names, trademarks, service marks, or product names of the
Licensor, except as required for reasonable and customary use in
describing the origin of the Work and reproducing the content of
the NOTICE file.

7. Disclaimer of Warranty. Unless required by applicable law or
agreed to in writing, Licensor provides the Work (and each
Contributor provides its Contributions) on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied, including, without limitation, any warranties or
conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY,
or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible
for determining the appropriateness of using or redistributing
the Work and assume any risks associated with Your exercise of
permissions under this License.

8. Limitation of Liability. In no event and under no legal
theory, whether in tort (including negligence), contract,
or otherwise, unless required by applicable law (such as
deliberate and grossly negligent acts) or agreed to in writing,
shall any Contributor be liable to You for damages, including
any direct, indirect, special, incidental, or consequential
damages of any character arising as a result of this License or
out of the use or inability to use the Work (including but not
limited to damages for loss of goodwill, work stoppage, computer
failure or malfunction, or any and all other commercial damages
or losses), even if such Contributor has been advised of the
possibility of such damages.

9. Accepting Warranty or Additional Liability. While
redistributing the Work or Derivative Works thereof, You may
choose to offer, and charge a fee for, acceptance of support,
warranty, indemnity, or other liability obligations and/or
rights consistent with this License. However, in accepting such
obligations, You may act only on Your own behalf and on Your
sole responsibility, not on behalf of any other Contributor,
and only if You agree to indemnify, defend, and hold each
Contributor harmless for any liability incurred by, or claims
asserted against, such Contributor by reason of your accepting
any such warranty or additional liability.
____________________________________________________________

TrueCrypt License Version 3.0

Software distributed under this license is distributed on an "AS
IS" BASIS WITHOUT WARRANTIES OF ANY KIND. THE AUTHORS AND
DISTRIBUTORS OF THE SOFTWARE DISCLAIM ANY LIABILITY. ANYONE WHO
USES, COPIES, MODIFIES, OR (RE)DISTRIBUTES ANY PART OF THE
SOFTWARE IS, BY SUCH ACTION(S), ACCEPTING AND AGREEING TO BE
BOUND BY ALL TERMS AND CONDITIONS OF THIS LICENSE. IF YOU DO NOT
ACCEPT THEM, DO NOT USE, COPY, MODIFY, NOR (RE)DISTRIBUTE THE
SOFTWARE, NOR ANY PART(S) THEREOF.


I. Definitions

1. "This Product" means the work (including, but not limited to,
source code, graphics, texts, and accompanying files) made
available under and governed by this version of this license
("License"), as may be indicated by, but is not limited to,
copyright notice(s) attached to or included in the work.

2. "You" means (and "Your" refers to) an individual or a legal
entity (e.g., a non-profit organization, commercial
organization, government agency, etc.) exercising permissions
granted by this License.

3. "Modification" means (and "modify" refers to) any alteration
of This Product, including, but not limited to, addition to or
deletion from the substance or structure of This Product,
translation into another language, repackaging, alteration or
removal of any file included with This Product, and addition of
any new files to This Product.

4. "Your Product" means This Product modified by You, or any
work You derive from (or base on) any part of This Product. In
addition, "Your Product" means any work in which You include any
(modified or unmodified) portion of This Product. However, if
the work in which you include it is an aggregate software
distribution (such as an operating system distribution or a
cover CD-ROM of a magazine) containing multiple separate
products, then the term "Your Product" includes only those
products (in the aggregate software distribution) that use,
include, or depend on a modified or unmodified version of This
Product (and the term "Your Product" does not include the whole
aggregate software distribution). For the purposes of this
License, a product suite consisting of two or more products is
considered a single product (operating system distributions and
cover media of magazines are not considered product suites).

5. "Distribution" means (and "distribute" refers to), regardless
of means or methods, conveyance, transfer, providing, or making
available of This/Your Product or portions thereof to third
parties (including, but not limited to, making This/Your
Product, or portions thereof, available for download to third
parties, whether or not any third party has downloaded the
product, or any portion thereof, made available for download).



II. Use, Copying, and Distribution of This Product

1. Provided that You comply with all applicable terms and
conditions of this License, You may make copies of This Product
(unmodified) and distribute copies of This Product (unmodified)
that are not included in another product forming Your Product
(except as permitted under Chapter III). Note: For terms and
conditions for copying and distribution of modified versions of
This Product, see Chapter III.

2. Provided that You comply with all applicable terms and
conditions of this License, You may use This Product freely (see
also Chapter III) on any number of computers/systems for non-
commercial and/or commercial purposes.



III. Modification, Derivation, and Inclusion in Other Products

1. If all conditions specified in the following paragraphs in
this Chapter (III) are met (for exceptions, see Section III.2)
and if You comply with all other applicable terms and conditions
of this License, You may modify This Product (thus forming Your
Product), derive new works from This Product or portions thereof
(thus forming Your Product), include This Product or portions
thereof in another product (thus forming Your Product, unless
defined otherwise in Chapter I), and You may use (for non-
commercial and/or commercial purposes), copy, and/or distribute
Your Product.

    a. The name of Your Product (or of Your modified version of
    This Product) must not contain the name TrueCrypt (for
    example, the following names are not allowed: TrueCrypt,
    TrueCrypt+, TrueCrypt Professional, iTrueCrypt, etc.) nor
    any other names confusingly similar to the name TrueCrypt
    (e.g., True-Crypt, True Crypt, TruKrypt, etc.)

    All occurrences of the name TrueCrypt that could reasonably
    be considered to identify Your Product must be removed from
    Your Product and from any associated materials. Logo(s)
    included in (or attached to) Your Product (and in/to
    associated materials) must not incorporate and must not be
    confusingly similar to any of the TrueCrypt logos
    (including, but not limited to, the non-textual logo
    consisting primarily of a key in stylized form) or
    portion(s) thereof. All graphics contained in This Product
    (logos, icons, etc.) must be removed from Your Product (or
    from Your modified version of This Product) and from any
    associated materials.

    b. The following phrases must be removed from Your Product
    and from any associated materials, except the text of this
    License: "A TrueCrypt Foundation Release", "Released by
    TrueCrypt Foundation", "This is a TrueCrypt Foundation
    release."

    c. Phrase "Based on TrueCrypt, freely available at
    http://www.truecrypt.org/" must be displayed by Your Product
    (if technically feasible) and contained in its
    documentation. Alternatively, if This Product or its portion
    You included in Your Product constitutes only a minor
    portion of Your Product, phrase "Portions of this product
    are based in part on TrueCrypt, freely available at
    http://www.truecrypt.org/" may be displayed instead. In each
    of the cases mentioned above in this paragraph,
    "http://www.truecrypt.org/" must be a hyperlink (if
    technically feasible) pointing to http://www.truecrypt.org/
    and You may freely choose the location within the user
    interface (if there is any) of Your Product (e.g., an
    "About" window, etc.) and the way in which Your Product will
    display the respective phrase.

    Your Product (and any associated materials, e.g., the
    documentation, the content of the official web site of Your
    Product, etc.) must not present any Internet address
    containing the domain name truecrypt.org (or any domain name
    that forwards to the domain name truecrypt.org) in a manner
    that might suggest that it is where information about Your
    Product may be obtained or where bugs found in Your Product
    may be reported or where support for Your Product may be
    available or otherwise attempt to indicate that the domain
    name truecrypt.org is associated with Your Product.

    d. The complete source code of Your Product must be freely
    and publicly available (for exceptions, see Section III.2)
    at least until You cease to distribute Your Product. This
    condition can be met in one or both of the following ways:
    (i) You include the complete source code of Your Product
    with every copy of Your Product that You make and distribute
    and You make all such copies of Your Product available to
    the general public free of charge, and/or (ii) You include
    information (valid and correct at least until You cease to
    distribute Your Product) about where the complete source
    code of Your Product can be obtained free of charge (e.g.,
    an Internet address) or for a reasonable reproduction fee
    with every copy of Your Product that You make and distribute
    and, if there is a web site officially associated with Your
    Product, You include the aforementioned information about
    the source code on a freely and publicly accessible web
    page to which such web site links via an easily viewable
    hyperlink (at least until You cease to distribute Your
    Product).

    The source code of Your Product must not be deliberately
    obfuscated and it must not be in an intermediate form (e.g.,
    the output of a preprocessor). Source code means the
    preferred form in which a programmer would usually modify
    the program.

    Portions of the source code of Your Product not contained in
    This Product (e.g., portions added by You in creating Your
    Product, whether created by You or by third parties) must be
    available under license(s) that (however, see also
    Subsection III.1.e) allow(s) anyone to modify and derive new
    works from the portions of the source code that are not
    contained in This Product and to use, copy, and redistribute
    such modifications and/or derivative works. The license(s)
    must be perpetual, non-exclusive, royalty-free, no-charge,
    and worldwide, and must not invalidate, weaken, restrict,
    interpret, amend, modify, interfere with or otherwise affect
    any part, term, provision, or clause of this License. The
    text(s) of the license(s) must be included with every copy
    of Your Product that You make and distribute.

    e. You must not change the license terms of This Product in
    any way (adding any new terms is considered changing the
    license terms even if the original terms are retained),
    which means, e.g., that no part of This Product may be put
    under another license. You must keep intact all the legal
    notices contained in the source code files. You must include
    the following items with every copy of Your Product that You
    make and distribute: a clear and conspicuous notice stating
    that Your Product or portion(s) thereof is/are governed by
    this version of the TrueCrypt License, a verbatim copy of
    this version of the TrueCrypt License (as contained herein),
    a clear and conspicuous notice containing information about
    where the included copy of the License can be found, and an
    appropriate copyright notice.


2. You are not obligated to comply with Subsection III.1.d if
Your Product is not distributed (i.e., Your Product is available
only to You).



IV. Disclaimer of Liability, Disclaimer of Warranty,
Indemnification

You expressly acknowledge and agree to the following:

1. IN NO EVENT WILL ANY (CO)AUTHOR OF THIS PRODUCT, OR ANY
APPLICABLE INTELLECTUAL-PROPERTY OWNER, OR ANY OTHER PARTY WHO
MAY COPY AND/OR (RE)DISTRIBUTE THIS PRODUCT OR PORTIONS THEREOF,
AS MAY BE PERMITTED HEREIN, BE LIABLE TO YOU OR TO ANY OTHER
PARTY FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, ANY
DIRECT, INDIRECT, GENERAL, SPECIAL, INCIDENTAL, PUNITIVE,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, CORRUPTION OR LOSS OF DATA, ANY LOSSES SUSTAINED BY YOU OR
THIRD PARTIES, A FAILURE OF THIS PRODUCT TO OPERATE WITH ANY
OTHER PRODUCT, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, OR
BUSINESS INTERRUPTION), WHETHER IN CONTRACT, STRICT LIABILITY,
TORT (INCLUDING, BUT NOT LIMITED TO, NEGLIGENCE) OR OTHERWISE,
ARISING OUT OF THE USE, COPYING, MODIFICATION, OR
(RE)DISTRIBUTION OF THIS PRODUCT (OR A PORTION THEREOF) OR OF
YOUR PRODUCT (OR A PORTION THEREOF), OR INABILITY TO USE THIS
PRODUCT (OR A PORTION THEREOF), EVEN IF SUCH DAMAGES (OR THE
POSSIBILITY OF SUCH DAMAGES) ARE/WERE PREDICTABLE OR KNOWN TO
ANY (CO)AUTHOR, INTELLECTUAL-PROPERTY OWNER, OR ANY OTHER PARTY.

2. THIS PRODUCT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT
LIMITED TO, THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE, AND NON-INFRINGEMENT. THE ENTIRE RISK AS TO
THE QUALITY AND PERFORMANCE OF THIS PRODUCT IS WITH YOU. SHOULD
THIS PRODUCT PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

3. THIS PRODUCT MAY INCORPORATE IMPLEMENTATIONS OF CRYPTOGRAPHIC
ALGORITHMS THAT ARE REGULATED (E.G., SUBJECT TO EXPORT/IMPORT
CONTROL REGULATIONS) OR ILLEGAL IN SOME COUNTRIES. IT IS SOLELY
YOUR RESPONSIBILITY TO VERIFY THAT IT IS LEGAL TO IMPORT AND/OR
(RE)EXPORT AND/OR USE THIS PRODUCT (OR PORTIONS THEREOF) IN
COUNTRIES WHERE YOU INTEND TO USE IT AND/OR TO WHICH YOU INTEND
TO IMPORT IT AND/OR FROM WHICH YOU INTEND TO EXPORT IT, AND IT
IS SOLELY YOUR RESPONSIBILITY TO COMPLY WITH ANY APPLICABLE
REGULATIONS, RESTRICTIONS, AND LAWS.

4. YOU SHALL INDEMNIFY, DEFEND AND HOLD ALL (CO)AUTHORS OF THIS
PRODUCT, AND APPLICABLE INTELLECTUAL-PROPERTY OWNERS, HARMLESS
FROM AND AGAINST ANY AND ALL LIABILITY, DAMAGES, LOSSES,
SETTLEMENTS, PENALTIES, FINES, COSTS, EXPENSES (INCLUDING
REASONABLE ATTORNEYS' FEES), DEMANDS, CAUSES OF ACTION, CLAIMS,
ACTIONS, PROCEEDINGS, AND SUITS, DIRECTLY RELATED TO OR ARISING
OUT OF YOUR USE, INABILITY TO USE, COPYING, (RE)DISTRIBUTION,
IMPORT AND/OR (RE)EXPORT OF THIS PRODUCT (OR PORTIONS THEREOF)
AND/OR YOUR BREACH OF ANY TERM OF THIS LICENSE.



V. Trademarks

This License does not grant permission to use trademarks
associated with (or applying to) This Product, except for fair
use as defined by applicable law and except for use expressly
permitted or required by this License. Any attempt otherwise to
use trademarks associated with (or applying to) This Product
automatically and immediately terminates Your rights under This
License and may constitute trademark infringement (which may be
prosecuted).



VI. General Terms and Conditions, Miscellaneous Provisions

1. ANYONE WHO USES AND/OR COPIES AND/OR MODIFIES AND/OR CREATES
DERIVATIVE WORKS OF AND/OR (RE)DISTRIBUTES THIS PRODUCT, OR ANY
PORTION(S) THEREOF, IS, BY SUCH ACTION(S), AGREEING TO BE BOUND
BY AND ACCEPTING ALL TERMS AND CONDITIONS OF THIS LICENSE (AND
THE RESPONSIBILITIES AND OBLIGATIONS CONTAINED IN THIS LICENSE).
IF YOU DO NOT ACCEPT (AND AGREE TO BE BOUND BY) ALL TERMS AND
CONDITIONS OF THIS LICENSE, DO NOT USE, COPY, MODIFY, CREATE
DERIVATIVE WORKS OF, NOR (RE)DISTRIBUTE THIS PRODUCT, NOR ANY
PORTION(S) THEREOF.

2. YOU MAY NOT USE, MODIFY, COPY, CREATE DERIVATIVE WORKS OF,
(RE)DISTRIBUTE, OR SUBLICENSE THIS PRODUCT, OR PORTION(S)
THEREOF, EXCEPT AS EXPRESSLY PROVIDED IN THIS LICENSE (EVEN IF
APPLICABLE LAW GIVES YOU MORE RIGHTS). ANY ATTEMPT (EVEN IF
PERMITTED BY APPLICABLE LAW) OTHERWISE TO USE, MODIFY, COPY,
CREATE DERIVATIVE WORKS OF, (RE)DISTRIBUTE, OR SUBLICENSE THIS
PRODUCT, OR PORTION(S) THEREOF, AUTOMATICALLY AND IMMEDIATELY
TERMINATES YOUR RIGHTS UNDER THIS LICENSE AND CAN CONSTITUTE
COPYRIGHT INFRINGEMENT (WHICH MAY BE PROSECUTED). ANY CONDITIONS
AND RESTRICTIONS CONTAINED IN THIS LICENSE ARE ALSO LIMITATIONS
ON THE SCOPE OF THIS LICENSE AND ALSO DEFINE THE SCOPE OF YOUR
RIGHTS UNDER THIS LICENSE. YOUR FAILURE TO COMPLY WITH THE TERMS
AND CONDITIONS OF THIS LICENSE OR FAILURE TO PERFORM ANY
APPLICABLE OBLIGATION IMPOSED BY THIS LICENSE AUTOMATICALLY AND
IMMEDIATELY TERMINATES YOUR RIGHTS UNDER THIS LICENSE AND CAN
CAUSE OR BE CONSIDERED COPYRIGHT INFRINGEMENT (WHICH MAY BE
PROSECUTED). NOTHING IN THIS LICENSE SHALL IMPLY OR BE CONSTRUED
AS A PROMISE, OBLIGATION, OR COVENANT NOT TO SUE FOR COPYRIGHT
OR TRADEMARK INFRINGEMENT IF YOU DO NOT COMPLY WITH THE TERMS
AND CONDITIONS OF THIS LICENSE.

3. This License does not constitute or imply a waiver of any
intellectual property rights except as may be otherwise
expressly provided in this License. This License does not
transfer, assign, or convey any intellectual property rights
(e.g., it does not transfer ownership of copyrights or
trademarks).

4. Subject to the terms and conditions of this License, You may
allow a third party to use Your copy of This Product (or a copy
that You make and distribute, or Your Product) provided that the
third party explicitly accepts and agrees to be bound by all
terms and conditions of this License and the third party is not
prohibited from using This Product (or portions thereof) by this
License (see, e.g., Section VI.7) or by applicable law. However,
You are not obligated to ensure that the third party accepts
(and agrees to be bound by all terms of) this License if You
distribute only the self-extracting package (containing This
Product) that does not allow the user to install (nor extract)
the files contained in the package until he or she accepts and
agrees to be bound by all terms and conditions of this License.

5. Without specific prior written permission from the authors of
This Product (or from their common representative), You must not
use the name of This Product, the names of the authors of This
Product, or the names of the legal entities (or informal groups)
of which the authors were/are members/employees, to endorse or
promote Your Product or any work in which You include a modified
or unmodified version of This Product, or to endorse or promote
You or Your affiliates, or in a way that might suggest that Your
Product (or any work in which You include a modified or
unmodified version of This Product), You, or Your affiliates
is/are endorsed by one or more authors of This Product, or in a
way that might suggest that one or more authors of This Product
is/are affiliated with You (or Your affiliates) or directly
participated in the creation of Your Product or of any work in
which You include a modified or unmodified version of This
Product.

6. IF YOU ARE NOT SURE WHETHER YOU UNDERSTAND ALL PARTS OF THIS
LICENSE OR IF YOU ARE NOT SURE WHETHER YOU CAN COMPLY WITH ALL
TERMS AND CONDITIONS OF THIS LICENSE, YOU MUST NOT USE, COPY,
MODIFY, CREATE DERIVATIVE WORKS OF, NOR (RE)DISTRIBUTE THIS
PRODUCT, NOR ANY PORTION(S) OF IT. YOU SHOULD CONSULT WITH A
LAWYER.

7. IF (IN RELEVANT CONTEXT) ANY PROVISION OF CHAPTER IV OF THIS
LICENSE IS UNENFORCEABLE, INVALID, OR PROHIBITED UNDER
APPLICABLE LAW IN YOUR JURISDICTION, YOU HAVE NO RIGHTS UNDER
THIS LICENSE AND YOU MUST NOT USE, COPY, MODIFY, CREATE
DERIVATIVE WORKS OF, NOR (RE)DISTRIBUTE THIS PRODUCT, NOR ANY
PORTION(S) THEREOF.

8. Except as otherwise provided in this License, if any
provision of this License, or a portion thereof, is found to be
invalid or unenforceable under applicable law, it shall not
affect the validity or enforceability of the remainder of this
License, and such invalid or unenforceable provision shall be
construed to reflect the original intent of the provision and
shall be enforced to the maximum extent permitted by applicable
law so as to effect the original intent of the provision as
closely as possible.

____________________________________________________________


Third-Party Licenses

This Product contains components that were created by third
parties and that are governed by third-party licenses, which are
contained hereinafter (separated by lines consisting of
underscores). Each of the third-party licenses applies only to
(portions of) the source code file(s) in which the third-party
license is contained or in which it is explicitly referenced,
and to compiled or otherwise processed forms of such source
code. None of the third-party licenses applies to This Product
as a whole, even when it uses terms such as "product",
"program", or any other equivalent terms/phrases. This Product
as a whole is governed by the TrueCrypt License (see above).
Some of the third-party components have been modified by the
authors of This Product. Unless otherwise stated, such
modifications and additions are governed by the TrueCrypt
License (see above). Note: Unless otherwise stated, graphics and
files that are not part of the source code are governed by the
TrueCrypt License.

____________________________________________________________

License agreement for Encryption for the Masses.

Copyright (C) 1998-2000 Paul Le Roux. All Rights Reserved.

This product can be copied and distributed free of charge,
including source code.

You may modify this product and source code, and distribute such
modifications, and you may derive new works based on this
product, provided that:

1. Any product which is simply derived from this product cannot
be called E4M, or Encryption for the Masses.

2. If you use any of the source code in your product, and your
product is distributed with source code, you must include this
notice with those portions of this source code that you use.

Or,

If your product is distributed in binary form only, you must
display on any packaging, and marketing materials which
reference your product, a notice which states:

"This product uses components written by Paul Le Roux
<pleroux@swprofessionals.com>"

3. If you use any of the source code originally by Eric Young,
you must in addition follow his terms and conditions.

4. Nothing requires that you accept this License, as you have
not signed it. However, nothing else grants you permission to
modify or distribute the product or its derivative works.

These actions are prohibited by law if you do not accept this
License.

5. If any of these license terms is found to be to broad in
scope, and declared invalid by any court or legal process, you
agree that all other terms shall not be so affected, and shall
remain valid and enforceable.

6. THIS PROGRAM IS DISTRIBUTED FREE OF CHARGE, THEREFORE THERE
IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW. UNLESS OTHERWISE STATED THE PROGRAM IS PROVIDED
"AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS
WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE
COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

7. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN
WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY
MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL,
INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR
INABILITY TO USE THE PROGRAM, INCLUDING BUT NOT LIMITED TO LOSS
OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH
ANY OTHER PROGRAMS, EVEN IF SUCH HOLDER OR OTHER PARTY HAD
PREVIOUSLY BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
____________________________________________________________

Copyright (c) 1998-2008, Brian Gladman, Worcester, UK.
All rights reserved.

LICENSE TERMS

The free distribution and use of this software is allowed (with
or without changes) provided that:

 1. source code distributions include the above copyright
    notice, this list of conditions and the following
    disclaimer;

 2. binary distributions include the above copyright notice,
    this list of conditions and the following disclaimer in
    their documentation;

 3. the name of the copyright holder is not used to endorse
    products built using this software without specific written
    permission.

DISCLAIMER

This software is provided 'as is' with no explicit or implied
warranties in respect of its properties, including, but not
limited to, correctness and/or fitness for purpose.
____________________________________________________________

Copyright (C) 2002-2004 Mark Adler, all rights reserved
version 1.8, 9 Jan 2004

This software is provided 'as-is', without any express or
implied warranty.  In no event will the author be held liable
for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any
purpose, including commercial applications, and to alter it and
redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you
   must not claim that you wrote the original software. If you
   use this software in a product, an acknowledgment in the
   product documentation would be appreciated but is not
   required.
2. Altered source versions must be plainly marked as such, and
   must not be misrepresented as being the original software.
3. This notice may not be removed or altered from any source
   distribution.
____________________________________________________________
_LICENSE_END

[ $? -ne 0 ] && show_exit_message 'Error while extracting license' && exit 1


# Task selection

INSTALL=-1

if [ $XMESSAGE -eq 1 ]
then

	cat <<_END | xmessage -title "VeraCrypt Setup" -center -file - -buttons "Exit:1,Extract .$PACKAGE_TYPE Package File:20,Install VeraCrypt:10" -default 'Install VeraCrypt'
VeraCrypt $VERSION Setup
====================
 VeraCrypt is a free disk encryption software brought to you by IDRIX
 (http://www.idrix.fr) and that is based on TrueCrypt.
 It is a software system for establishing and maintaining an
 on-the-fly-encrypted volume (data storage device). On-the-fly encryption
 means that data are automatically encrypted or decrypted right before they
 are loaded or saved, without any user intervention. No data stored on an
 encrypted volume can be read (decrypted) without using the correct
 password/keyfile(s) or correct encryption keys. Entire file system is
 encrypted (e.g., file names, folder names, contents of every file,
 free space, meta data, etc).

Please select one of the below options:

_END

	SEL=$?

	case $SEL in
		1)	exit 1
			;;
		10)	INSTALL=1
			;;
		20)	INSTALL=0
			;;
	esac

else

	while [ $INSTALL -eq -1 ]
	do
		clear
		cat <<_MENU_END
VeraCrypt $VERSION Setup
____________________


Installation options:

 1) Install $PACKAGE_NAME
 2) Extract package file $PACKAGE_NAME and place it to $PACKAGE_DIR

_MENU_END

		printf 'To select, enter 1 or 2: '

		read SEL
		[ -z "$SEL" ] && SEL=1

		case $SEL in
			1)	INSTALL=1
				;;
			2)	INSTALL=0
				;;
		esac
	done

fi


# Administrator privileges check

SUDO=sudo

if [ $INSTALL -eq 1 -a $(id -u) -ne 0 ]
then
	if ! which $SUDO >/dev/null 2>/dev/null
	then
		show_exit_message "Error: Administrator privileges required ($SUDO command is not installed)"
		rm -f $LICENSE
		exit 1
	fi
else
	unset SUDO
fi

[ -n "$SUDO" -a $GUI -eq 1 ] && which gksudo >/dev/null 2>/dev/null && SUDO="gksudo -D 'VeraCrypt Setup' --"
[ -n "$SUDO" -a $GUI -eq 1 ] && which kdesudo >/dev/null 2>/dev/null && SUDO="kdesudo -d --comment 'VeraCrypt Setup' --"


# License agreement

if [ $XMESSAGE -eq 1 ]
then

# GUI license agreement

	cat <<_END | cat - $LICENSE | xmessage -title "VeraCrypt Setup" -center -file - -buttons 'I accept and agree to be bound by the license terms:10,I do not accept:20'

Before you can use, extract, or install VeraCrypt, you must accept these
license terms.

IMPORTANT: By clicking the left button below this text field, you accept
these license terms and agree to be bound by and to comply with them.
Press Page Down key or use the scroll bar to see the rest of the license.



_END

	SEL=$?

	rm -f $LICENSE
	if [ $SEL -ne 10 ]
	then
		show_exit_message 'Installation/extraction aborted'
		exit 1
	fi

else

# Console license agreement

printf '\nBefore you can use, extract, or install VeraCrypt, you must accept the\n'
printf 'terms of the VeraCrypt License.\n\nPress Enter to display the license terms... '
read A

MORE=more
HASLESS=0
which less >/dev/null 2>/dev/null && HASLESS=1
if [ $HASLESS -eq 1 ]
then
	MORE='less -E -X'
fi
	cat <<_END | cat - $LICENSE | $MORE

Press Enter or space bar to see the rest of the license.


_END
	if [ $? -ne 0 ]
	then
		if [ $HASLESS -eq 1 ]
		then
# use less without -X as it is not supported by some versions (busybox case)
			MORE='less -E'
			cat <<_END | cat - $LICENSE | $MORE

Press Enter or space bar to see the rest of the license.


_END
			[ $? -ne 0 ] && exit 1
		else
			exit 1
		fi
	fi

	rm -f $LICENSE

	ACCEPTED=0
	while [ $ACCEPTED -eq 0 ]
	do
		printf '\n\nDo you accept and agree to be bound by the license terms? (yes/no): '

		read SEL

		case $SEL in
			y|Y|yes|YES)
				ACCEPTED=1
				;;
			n|N|no|NO)
				exit 0
				;;
		esac
	done
fi


# Package extraction

[ $GUI -eq 0 ] && echo

if ! tail -n +$PACKAGE_START "$0" >$PACKAGE
then
	show_exit_message "Error: Extraction to $PACKAGE failed"
	exit 1
fi


# Package installation

if [ "$PACKAGE_TYPE" = "tar" ]
then
	if ! which fusermount >/dev/null 2>/dev/null || ! which dmsetup >/dev/null 2>/dev/null || ! service pcscd status >/dev/null 2>/dev/null
	then
		show_message "$(cat <<_INFO
Requirements for Running VeraCrypt:
-----------------------------------

 - FUSE library and tools
 - device mapper tools
 - PC/SC Lite (optional)

_INFO
)"
		[ $GUI -eq 0 ] && echo && echo Press Enter to continue... && read A
	fi

	show_message "$(cat <<_INFO
Uninstalling VeraCrypt:
-----------------------

To uninstall VeraCrypt, please run 'veracrypt-uninstall.sh'.

_INFO
)"
	[ $GUI -eq 0 ] && echo
fi

if [ $INSTALL -eq 1 ]
then

	INSTALLED=0

	if [ $GUI -eq 1 ]
	then
		if [ $XTERM -eq 1 ]
		then
			exec xterm -T 'VeraCrypt Setup' -e sh -c "echo Installing package...; $SUDO $PACKAGE_INSTALLER $PACKAGE_INSTALLER_OPTS $PACKAGE; rm -f $PACKAGE; $SUDO update-mime-database /usr/share/mime >/dev/null 2>&1; $SUDO update-desktop-database -q; echo; echo Press Enter to exit...; read A"
		else
			if [ $GTERM -eq 1 ]
			then
				exec gnome-terminal --title='VeraCrypt Setup' -- sh -c "echo Installing package...; $SUDO $PACKAGE_INSTALLER $PACKAGE_INSTALLER_OPTS $PACKAGE; rm -f $PACKAGE; $SUDO update-mime-database /usr/share/mime >/dev/null 2>&1; $SUDO update-desktop-database -q; echo; echo Press Enter to exit...; read A"
			else
				if [ $KTERM -eq 1 ]
				then
					exec konsole --qwindowtitle 'VeraCrypt Setup' -e sh -c "echo Installing package...; $SUDO $PACKAGE_INSTALLER $PACKAGE_INSTALLER_OPTS $PACKAGE; rm -f $PACKAGE; $SUDO update-mime-database /usr/share/mime >/dev/null 2>&1; $SUDO update-desktop-database -q; echo; echo Press Enter to exit...; read A"
				fi
			fi
		fi
	else
		echo 'Installing package...'
		$SUDO $PACKAGE_INSTALLER $PACKAGE_INSTALLER_OPTS $PACKAGE && INSTALLED=1 && $SUDO update-mime-database /usr/share/mime >/dev/null 2>&1 && $SUDO update-desktop-database -q

		if [ $INSTALLED -eq 1 ]
		then
			show_exit_message ''
		fi
	fi

	rm -f $PACKAGE
	if [ $INSTALLED -ne 1 ]
	then
		show_exit_message 'Error: VeraCrypt installation failed'
		exit 1
	fi
else
	show_exit_message "Installation package '$PACKAGE_NAME' extracted and placed in '$PACKAGE_DIR'"
fi

exit 0
