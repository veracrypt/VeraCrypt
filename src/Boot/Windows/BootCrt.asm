;
; Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.
;
; Governed by the TrueCrypt License 3.0 the full text of which is contained in
; the file License.txt included in TrueCrypt binary and source code distribution
; packages.
;

.MODEL tiny, C
.386

INCLUDE BootDefs.i

EXTERNDEF main:NEAR

_TEXT SEGMENT
ORG TC_COM_EXECUTABLE_OFFSET

start:
	jmp main

_TEXT ENDS
END start
