0x430400  sub esp, 0x14
0x430403  mov eax, dword ptr [esp + 0x1c]
0x430407  mov ecx, dword ptr [esp + 0x20]
0x43040b  mov edx, dword ptr [esp + 0x24]
0x43040f  mov dword ptr [esp], eax
0x430413  mov eax, dword ptr [esp + 0x28]
0x430417  push esi
0x430418  mov dword ptr [esp + 0x10], eax
0x43041c  mov eax, dword ptr [esp + 0x1c]
0x430420  push edi
0x430421  mov dword ptr [esp + 0xc], ecx
0x430425  mov ecx, 5
0x43042a  lea esi, [esp + 8]
0x43042e  mov edi, eax
0x430430  mov dword ptr [esp + 0x10], edx
0x430434  rep movsd dword ptr es:[edi], dword ptr [esi]
0x430436  pop edi
0x430437  pop esi
0x430438  add esp, 0x14
0x43043b  ret 
